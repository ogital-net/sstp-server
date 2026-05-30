//! Cross-runtime PPP-auth dispatcher.
//!
//! Session tasks live on the per-worker `current_thread` I/O runtime
//! and must never block waiting for RADIUS — a slow authenticator
//! would head-of-line block every other connection on that worker.
//! [`AuthBridge`] decouples the two: the session task hands a
//! [`PapJob`] (or, later, [`MsChapJob`] / [`EapJob`]) across an MPSC
//! channel to the auth runtime, which runs the RADIUS round-trip
//! and returns the verdict through a `oneshot` the session task
//! awaits.
//!
//! The bridge owns a single shared [`RadiusClient`] (one UDP socket
//! with the usual identifier-allocation + retry policy) and one
//! dispatcher task per process. Per-request work is spawned onto the
//! auth runtime so a stuck server can't stall the queue.

use std::net::SocketAddr;
use std::sync::Arc;

use radius_tokio::client::RadiusClient;
use tokio::runtime::Handle;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

use crate::auth::client::{authenticate_chap_md5, authenticate_pap};
use crate::auth::request::AccessRequestCtx;
use crate::auth::{AuthAccept, AuthError};
use crate::ppp::{AssignedAddrs, AuthVerdict};
use crate::shape::ShapingPolicy;

/// Bounded depth of the dispatcher's inbound queue. A backlog past
/// this signals a RADIUS outage; we'd rather drop new auth requests
/// (which surface as `Reject("auth dispatcher unavailable")`) than
/// hold the queue open indefinitely.
const QUEUE_DEPTH: usize = 1024;

/// A PAP credential to be verified against RADIUS.
#[derive(Debug)]
pub struct PapJob {
    pub username: String,
    pub password: Vec<u8>,
    /// SSTP peer's source address — used as `Calling-Station-Id`.
    pub peer: SocketAddr,
    /// Verdict channel. The dispatcher always sends exactly one
    /// reply on this; a dropped sender surfaces as a Reject.
    pub reply: oneshot::Sender<PapOutcome>,
}

/// Bridge-level reject helper used by every method's failure paths
/// (queue closed, dispatcher gone, server unreachable, authoritative
/// reject). The `shaping` slot is always `None` on a reject.
fn reject(message: impl Into<Vec<u8>>) -> AuthOutcome {
    AuthOutcome {
        verdict: AuthVerdict::Reject {
            message: message.into(),
        },
        shaping: None,
    }
}

/// Project an [`AuthAccept`] into the bridge's outcome shape.
fn accept_outcome(accept: &AuthAccept) -> AuthOutcome {
    AuthOutcome {
        verdict: AuthVerdict::Accept {
            addrs: project_addrs(accept),
        },
        shaping: accept.shaping,
    }
}

/// Final reject emitted after exhausting every `--radius` server
/// without an authoritative answer.
fn transport_failure(last: Option<String>) -> AuthOutcome {
    let msg = last.map_or_else(
        || "auth failed: no RADIUS servers reachable".to_string(),
        |e| format!("auth failed: {e}"),
    );
    reject(msg.into_bytes())
}

/// Result of a PAP RADIUS round-trip, returned by
/// [`AuthBridge::submit_pap`].
///
/// `verdict` is what the in-process PPP driver consumes to gate the
/// PAP-Ack/-Nak frame and the IPCP transition. `shaping` is a
/// side-channel for the session task: present only on Accept, and
/// only when the Access-Accept carried a recognised shaping VSA
/// (today: `Mikrotik-Rate-Limit`). Kept separate from
/// [`AuthVerdict`] so the PPP layer doesn't grow a dependency on
/// [`crate::shape`].
/// Result of a single-roundtrip RADIUS authentication (PAP or
/// CHAP-MD5). Both methods produce the same outcome shape; method
/// identity lives at the [`Job`] / [`AuthBridge::submit_*`] level.
///
/// `verdict` feeds the in-process PPP driver. `shaping` is a
/// side-channel for the session task: present only on Accept, and
/// only when the Access-Accept carried a recognised shaping VSA
/// (today: `Mikrotik-Rate-Limit`). Kept separate from
/// [`AuthVerdict`] so the PPP layer doesn't grow a dependency on
/// [`crate::shape`].
#[derive(Debug)]
pub struct AuthOutcome {
    pub verdict: AuthVerdict,
    pub shaping: Option<ShapingPolicy>,
}

/// Backwards-compatible alias so existing call sites that pattern-
/// match on a method-specific outcome name keep compiling.
pub type PapOutcome = AuthOutcome;
pub type ChapOutcome = AuthOutcome;

/// A CHAP-MD5 response to be verified against RADIUS.
///
/// The 16-byte `response` and original `challenge` are forwarded to
/// the authenticator as `CHAP-Password` / `CHAP-Challenge`; we never
/// hash anything in-process.
#[derive(Debug)]
pub struct ChapJob {
    pub username: String,
    pub chap_id: u8,
    pub response: [u8; 16],
    pub challenge: [u8; 16],
    pub peer: SocketAddr,
    pub reply: oneshot::Sender<AuthOutcome>,
}

/// An MS-CHAPv2 response to be verified against RADIUS
/// (RFC 2548 §2.3.2 / [RFC 2759]).
#[derive(Debug)]
pub struct MsChapJob {
    pub username: String,
    /// CHAP packet identifier from the peer's `Response`.
    pub chap_id: u8,
    /// The 16-byte Authenticator-Challenge we sent in the CHAP
    /// `Challenge` packet.
    pub authenticator_challenge: [u8; 16],
    /// Peer-Challenge from the peer's MS-CHAPv2 Response field.
    pub peer_challenge: [u8; 16],
    /// 24-byte NT-Response from the peer's MS-CHAPv2 Response.
    pub nt_response: [u8; 24],
    /// MS-CHAPv2 Flags byte (typically 0).
    pub flags: u8,
    pub peer: SocketAddr,
    pub reply: oneshot::Sender<MsChapOutcome>,
}

/// Result of an MS-CHAPv2 RADIUS round-trip.
///
/// In addition to [`AuthVerdict`] + shaping, an Accept carries the
/// `MS-CHAP2-Success` Authenticator-Response body the driver must
/// echo verbatim in the PPP CHAP `Success` packet ([RFC 2759] §6).
/// A Reject carries an `MS-CHAP-Error`-formatted body when the
/// authenticator supplied one, otherwise [`None`] and the driver
/// synthesises a minimal `E=691 R=0 V=3 M=...` payload from
/// `verdict`'s reject message.
#[derive(Debug)]
pub struct MsChapOutcome {
    pub verdict: AuthVerdict,
    pub shaping: Option<ShapingPolicy>,
    pub auth_response: Option<Vec<u8>>,
    pub error_string: Option<String>,
}

impl MsChapOutcome {
    /// Construct a Reject outcome with the given message and the
    /// MS-CHAPv2-specific Accept-only fields cleared.
    fn reject(message: impl Into<Vec<u8>>) -> Self {
        Self {
            verdict: AuthVerdict::Reject {
                message: message.into(),
            },
            shaping: None,
            auth_response: None,
            error_string: None,
        }
    }
}

enum Job {
    Pap(PapJob),
    Chap(ChapJob),
    MsChap(MsChapJob),
}

/// Cloneable handle to the auth dispatcher. Cheap to clone — wraps
/// an `mpsc::Sender`. Held by the session tasks that need to submit
/// auth.
#[derive(Clone)]
pub struct AuthBridge {
    tx: mpsc::Sender<Job>,
}

impl std::fmt::Debug for AuthBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthBridge").finish_non_exhaustive()
    }
}

impl AuthBridge {
    /// Construct the bridge and spawn its dispatcher on `handle`.
    ///
    /// Binds a single [`RadiusClient`] (UDP) on `bind_addr` —
    /// `0.0.0.0:0` in production so the kernel picks the ephemeral
    /// port. `servers` is the ordered list of authenticators to try
    /// in failover order, each paired with its shared secret.
    ///
    /// Async because the [`RadiusClient`] bind must run on the auth
    /// runtime so its UDP socket is registered with that reactor.
    /// Call site is typically `auth_runtime.block_on(...)` from
    /// `main` (outside any runtime) or `.await` from a test
    /// running on a multi-thread runtime.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`std::io::Error`] if binding the UDP
    /// socket fails.
    ///
    /// # Panics
    ///
    /// Panics if `servers` is empty — there is no useful default.
    /// Called once at startup from `main`, so failing fast is the
    /// right behaviour.
    pub async fn spawn(
        handle: &Handle,
        bind_addr: SocketAddr,
        servers: Vec<(SocketAddr, Arc<[u8]>)>,
        nas_identifier: Option<Arc<str>>,
    ) -> std::io::Result<Self> {
        assert!(
            !servers.is_empty(),
            "AuthBridge::spawn requires at least one RADIUS server",
        );
        let client = RadiusClient::bind(bind_addr).await?;
        let client = Arc::new(client);
        let servers = Arc::<[(SocketAddr, Arc<[u8]>)]>::from(servers);
        let (tx, mut rx) = mpsc::channel::<Job>(QUEUE_DEPTH);
        handle.spawn(async move {
            while let Some(job) = rx.recv().await {
                let client = Arc::clone(&client);
                let servers = Arc::clone(&servers);
                let nas = nas_identifier.clone();
                tokio::spawn(async move {
                    match job {
                        Job::Pap(j) => run_pap(client, servers, nas, j).await,
                        Job::Chap(j) => run_chap(client, servers, nas, j).await,
                        Job::MsChap(j) => run_mschapv2(client, servers, nas, j).await,
                    }
                });
            }
            debug!("auth dispatcher exiting (all senders dropped)");
        });
        Ok(Self { tx })
    }

    /// Submit a PAP credential. The returned future resolves when the
    /// auth runtime has produced a verdict. A full or closed queue
    /// surfaces as `Reject("auth dispatcher unavailable")` so the
    /// caller can drop the PPP session cleanly without special-
    /// casing transport errors.
    pub async fn submit_pap(
        &self,
        username: String,
        password: Vec<u8>,
        peer: SocketAddr,
    ) -> AuthOutcome {
        let (reply, rx) = oneshot::channel();
        self.dispatch_basic(
            Job::Pap(PapJob {
                username,
                password,
                peer,
                reply,
            }),
            rx,
        )
        .await
    }

    /// Submit a CHAP-MD5 response. Same backpressure / drop semantics
    /// as [`AuthBridge::submit_pap`].
    pub async fn submit_chap(
        &self,
        username: String,
        chap_id: u8,
        response: [u8; 16],
        challenge: [u8; 16],
        peer: SocketAddr,
    ) -> AuthOutcome {
        let (reply, rx) = oneshot::channel();
        self.dispatch_basic(
            Job::Chap(ChapJob {
                username,
                chap_id,
                response,
                challenge,
                peer,
                reply,
            }),
            rx,
        )
        .await
    }

    /// Internal: send `job` to the dispatcher and wait for the
    /// matching `AuthOutcome`. Surfaces full / closed queue and a
    /// dropped reply channel uniformly as a `Reject`.
    async fn dispatch_basic(&self, job: Job, rx: oneshot::Receiver<AuthOutcome>) -> AuthOutcome {
        if self.tx.send(job).await.is_err() {
            return reject(b"auth dispatcher unavailable".as_slice());
        }
        rx.await
            .unwrap_or_else(|_| reject(b"auth dispatcher dropped reply".as_slice()))
    }

    /// Submit an MS-CHAPv2 response. Same backpressure / drop
    /// semantics as [`AuthBridge::submit_pap`].
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_mschapv2(
        &self,
        username: String,
        chap_id: u8,
        authenticator_challenge: [u8; 16],
        peer_challenge: [u8; 16],
        nt_response: [u8; 24],
        flags: u8,
        peer: SocketAddr,
    ) -> MsChapOutcome {
        let (reply, rx) = oneshot::channel();
        let job = Job::MsChap(MsChapJob {
            username,
            chap_id,
            authenticator_challenge,
            peer_challenge,
            nt_response,
            flags,
            peer,
            reply,
        });
        if self.tx.send(job).await.is_err() {
            return MsChapOutcome::reject("auth dispatcher unavailable");
        }
        rx.await
            .unwrap_or_else(|_| MsChapOutcome::reject("auth dispatcher dropped reply"))
    }
}

async fn run_pap(
    client: Arc<RadiusClient>,
    servers: Arc<[(SocketAddr, Arc<[u8]>)]>,
    nas_identifier: Option<Arc<str>>,
    job: PapJob,
) {
    let peer_ip = job.peer.ip().to_string();
    let ctx = AccessRequestCtx {
        username: &job.username,
        calling_station_id: Some(&peer_ip),
        nas_identifier: nas_identifier.as_deref(),
    };

    let mut last_transport_err: Option<String> = None;
    for (addr, secret) in servers.iter() {
        match authenticate_pap(&client, *addr, secret, &ctx, &job.password).await {
            Ok(accept) => {
                let _ = job.reply.send(accept_outcome(&accept));
                return;
            }
            Err(AuthError::Rejected(msg)) => {
                let bytes = msg.unwrap_or_else(|| "access rejected".into()).into_bytes();
                let _ = job.reply.send(reject(bytes));
                return;
            }
            Err(e) => {
                warn!(radius = %addr, user = %job.username, error = %e, "RADIUS PAP attempt failed; trying next server");
                last_transport_err = Some(e.to_string());
            }
        }
    }
    let _ = job.reply.send(transport_failure(last_transport_err));
}

async fn run_chap(
    client: Arc<RadiusClient>,
    servers: Arc<[(SocketAddr, Arc<[u8]>)]>,
    nas_identifier: Option<Arc<str>>,
    job: ChapJob,
) {
    let peer_ip = job.peer.ip().to_string();
    let ctx = AccessRequestCtx {
        username: &job.username,
        calling_station_id: Some(&peer_ip),
        nas_identifier: nas_identifier.as_deref(),
    };

    let mut last_transport_err: Option<String> = None;
    for (addr, secret) in servers.iter() {
        match authenticate_chap_md5(
            &client,
            *addr,
            secret,
            &ctx,
            job.chap_id,
            &job.response,
            &job.challenge,
        )
        .await
        {
            Ok(accept) => {
                let _ = job.reply.send(accept_outcome(&accept));
                return;
            }
            Err(AuthError::Rejected(msg)) => {
                let bytes = msg.unwrap_or_else(|| "access rejected".into()).into_bytes();
                let _ = job.reply.send(reject(bytes));
                return;
            }
            Err(e) => {
                warn!(radius = %addr, user = %job.username, error = %e, "RADIUS CHAP attempt failed; trying next server");
                last_transport_err = Some(e.to_string());
            }
        }
    }
    let _ = job.reply.send(transport_failure(last_transport_err));
}

async fn run_mschapv2(
    client: Arc<RadiusClient>,
    servers: Arc<[(SocketAddr, Arc<[u8]>)]>,
    nas_identifier: Option<Arc<str>>,
    job: MsChapJob,
) {
    use radius_tokio::client::AccessOutcome;

    let peer_ip = job.peer.ip().to_string();
    let ctx = AccessRequestCtx {
        username: &job.username,
        calling_station_id: Some(&peer_ip),
        nas_identifier: nas_identifier.as_deref(),
    };

    let mut last_transport_err: Option<String> = None;
    for (addr, secret) in servers.iter() {
        let outcome = client
            .access_request(*addr, secret, |buf, _ra| {
                crate::auth::request::apply_mschapv2(
                    buf,
                    &ctx,
                    &job.authenticator_challenge,
                    job.chap_id,
                    &job.peer_challenge,
                    &job.nt_response,
                    job.flags,
                )
            })
            .await;
        match outcome {
            Ok(AccessOutcome::Accept {
                authenticator,
                attributes,
            }) => match crate::auth::reply::decode_accept(&attributes, secret, &authenticator) {
                Ok(accept) => {
                    let shaping = accept.shaping;
                    let auth_response = accept.mschap2_success.clone();
                    let _ = job.reply.send(MsChapOutcome {
                        verdict: AuthVerdict::Accept {
                            addrs: project_addrs(&accept),
                        },
                        shaping,
                        auth_response,
                        error_string: None,
                    });
                    return;
                }
                Err(e) => {
                    warn!(radius = %addr, user = %job.username, error = %e, "MS-CHAPv2 Access-Accept malformed; trying next server");
                    last_transport_err = Some(e.to_string());
                }
            },
            Ok(AccessOutcome::Reject { attributes, .. }) => {
                let error_string = crate::auth::reply::mschap_error(&attributes);
                let reason = crate::auth::reply::reject_reason(&attributes)
                    .or_else(|| error_string.clone())
                    .unwrap_or_else(|| "access rejected".into());
                let _ = job.reply.send(MsChapOutcome {
                    verdict: AuthVerdict::Reject {
                        message: reason.into_bytes(),
                    },
                    shaping: None,
                    auth_response: None,
                    error_string,
                });
                return;
            }
            Ok(AccessOutcome::Challenge { .. }) => {
                warn!(radius = %addr, user = %job.username, "MS-CHAPv2: unexpected Access-Challenge; trying next server");
                last_transport_err = Some("unexpected Access-Challenge".into());
            }
            Err(e) => {
                let auth_err: AuthError = e.into();
                warn!(radius = %addr, user = %job.username, error = %auth_err, "RADIUS MS-CHAPv2 attempt failed; trying next server");
                last_transport_err = Some(auth_err.to_string());
            }
        }
    }
    let msg = last_transport_err.map_or_else(
        || "auth failed: no RADIUS servers reachable".into(),
        |e| format!("auth failed: {e}"),
    );
    let _ = job.reply.send(MsChapOutcome {
        verdict: AuthVerdict::Reject {
            message: msg.into_bytes(),
        },
        shaping: None,
        auth_response: None,
        error_string: None,
    });
}

fn project_addrs(accept: &AuthAccept) -> AssignedAddrs {
    let mtu = accept
        .framed_mtu
        .and_then(|m| u16::try_from(m).ok())
        .map(|m| m.clamp(576, 1500));
    AssignedAddrs {
        ip: accept.framed_ip.octets(),
        mtu,
        dns1: accept.primary_dns.map(|a| a.octets()),
        dns2: accept.secondary_dns.map(|a| a.octets()),
        nbns1: accept.primary_nbns.map(|a| a.octets()),
        nbns2: accept.secondary_nbns.map(|a| a.octets()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use radius_tokio::{Code, PacketBuffer, Reply, dict::rfc};
    use std::net::Ipv4Addr;
    use tokio::net::UdpSocket;

    async fn one_shot_responder<F>(mut respond: F) -> (SocketAddr, tokio::task::JoinHandle<()>)
    where
        F: FnMut(u8, [u8; 16]) -> PacketBuffer + Send + 'static,
    {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let addr = sock.local_addr().expect("addr");
        let h = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (n, peer) = sock.recv_from(&mut buf).await.expect("recv");
            let datagram = &buf[..n];
            let id = datagram[1];
            let mut ra = [0u8; 16];
            ra.copy_from_slice(&datagram[4..20]);
            let reply = respond(id, ra);
            sock.send_to(reply.as_bytes(), peer).await.expect("send");
        });
        (addr, h)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pap_accept_projects_addrs() {
        let secret: Arc<[u8]> = Arc::from(b"shh".as_slice());
        let secret_for_server = secret.clone();
        let (server_addr, _h) = one_shot_responder(move |id, ra| {
            let mut reply = Reply::new(Code::ACCESS_ACCEPT, id);
            reply
                .add(rfc::attrs::FRAMED_IP_ADDRESS, Ipv4Addr::new(10, 9, 8, 7))
                .unwrap();
            reply.seal_for(&ra, &secret_for_server)
        })
        .await;

        let bridge = AuthBridge::spawn(
            &Handle::current(),
            "127.0.0.1:0".parse().unwrap(),
            vec![(server_addr, secret)],
            None,
        )
        .await
        .expect("spawn bridge");

        let outcome = bridge
            .submit_pap(
                "alice".into(),
                b"pw".to_vec(),
                "127.0.0.1:5000".parse().unwrap(),
            )
            .await;
        assert!(outcome.shaping.is_none());
        match outcome.verdict {
            AuthVerdict::Accept { addrs } => {
                assert_eq!(addrs.ip, [10, 9, 8, 7]);
            }
            AuthVerdict::Reject { message } => {
                panic!(
                    "expected Accept, got Reject({:?})",
                    String::from_utf8_lossy(&message)
                )
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pap_reject_carries_reply_message() {
        let secret: Arc<[u8]> = Arc::from(b"shh".as_slice());
        let secret_for_server = secret.clone();
        let (server_addr, _h) = one_shot_responder(move |id, ra| {
            let mut reply = Reply::new(Code::ACCESS_REJECT, id);
            reply
                .add(rfc::attrs::REPLY_MESSAGE, "bad password")
                .unwrap();
            reply.seal_for(&ra, &secret_for_server)
        })
        .await;

        let bridge = AuthBridge::spawn(
            &Handle::current(),
            "127.0.0.1:0".parse().unwrap(),
            vec![(server_addr, secret)],
            None,
        )
        .await
        .expect("spawn bridge");

        let outcome = bridge
            .submit_pap(
                "alice".into(),
                b"pw".to_vec(),
                "127.0.0.1:5000".parse().unwrap(),
            )
            .await;
        assert!(outcome.shaping.is_none());
        match outcome.verdict {
            AuthVerdict::Reject { message } => {
                assert_eq!(&message, b"bad password");
            }
            AuthVerdict::Accept { .. } => panic!("expected Reject"),
        }
    }
}
