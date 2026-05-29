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

use crate::auth::client::authenticate_pap;
use crate::auth::request::AccessRequestCtx;
use crate::auth::{AuthAccept, AuthError};
use crate::ppp::{AssignedAddrs, AuthVerdict};

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
    /// Optional `NAS-Identifier`. Defaults to nothing; deployments
    /// that need a stable identifier will wire this through CLI in
    /// a later milestone.
    pub nas_identifier: Option<String>,
    /// Verdict channel. The dispatcher always sends exactly one
    /// reply on this; a dropped sender surfaces as a Reject.
    pub reply: oneshot::Sender<AuthVerdict>,
}

enum Job {
    Pap(PapJob),
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
                tokio::spawn(async move {
                    match job {
                        Job::Pap(j) => run_pap(client, servers, j).await,
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
        nas_identifier: Option<String>,
    ) -> AuthVerdict {
        let (reply, rx) = oneshot::channel();
        let job = Job::Pap(PapJob {
            username,
            password,
            peer,
            nas_identifier,
            reply,
        });
        if self.tx.send(job).await.is_err() {
            return AuthVerdict::Reject {
                message: b"auth dispatcher unavailable".to_vec(),
            };
        }
        rx.await.unwrap_or_else(|_| AuthVerdict::Reject {
            message: b"auth dispatcher dropped reply".to_vec(),
        })
    }
}

async fn run_pap(
    client: Arc<RadiusClient>,
    servers: Arc<[(SocketAddr, Arc<[u8]>)]>,
    job: PapJob,
) {
    let peer_ip = job.peer.ip().to_string();
    let ctx = AccessRequestCtx {
        username: &job.username,
        calling_station_id: Some(&peer_ip),
        nas_identifier: job.nas_identifier.as_deref(),
    };

    let mut last_transport_err: Option<String> = None;
    for (addr, secret) in servers.iter() {
        match authenticate_pap(&client, *addr, secret, &ctx, &job.password).await {
            Ok(accept) => {
                let _ = job.reply.send(AuthVerdict::Accept {
                    addrs: project_addrs(&accept),
                });
                return;
            }
            Err(AuthError::Rejected(msg)) => {
                // Authoritative reject — do not fail over to the
                // next server.
                let bytes = msg.unwrap_or_else(|| "access rejected".into()).into_bytes();
                let _ = job.reply.send(AuthVerdict::Reject { message: bytes });
                return;
            }
            Err(e) => {
                warn!(radius = %addr, user = %job.username, error = %e, "RADIUS auth attempt failed; trying next server");
                last_transport_err = Some(e.to_string());
            }
        }
    }
    let msg = last_transport_err.map_or_else(
        || "auth failed: no RADIUS servers reachable".into(),
        |e| format!("auth failed: {e}"),
    );
    let _ = job.reply.send(AuthVerdict::Reject {
        message: msg.into_bytes(),
    });
}

fn project_addrs(accept: &AuthAccept) -> AssignedAddrs {
    AssignedAddrs {
        ip: accept.framed_ip.octets(),
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

    async fn one_shot_responder<F>(
        mut respond: F,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>)
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
        )
        .await
        .expect("spawn bridge");

        let verdict = bridge
            .submit_pap(
                "alice".into(),
                b"pw".to_vec(),
                "127.0.0.1:5000".parse().unwrap(),
                None,
            )
            .await;
        match verdict {
            AuthVerdict::Accept { addrs } => {
                assert_eq!(addrs.ip, [10, 9, 8, 7]);
            }
            AuthVerdict::Reject { message } => {
                panic!("expected Accept, got Reject({:?})", String::from_utf8_lossy(&message))
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pap_reject_carries_reply_message() {
        let secret: Arc<[u8]> = Arc::from(b"shh".as_slice());
        let secret_for_server = secret.clone();
        let (server_addr, _h) = one_shot_responder(move |id, ra| {
            let mut reply = Reply::new(Code::ACCESS_REJECT, id);
            reply.add(rfc::attrs::REPLY_MESSAGE, "bad password").unwrap();
            reply.seal_for(&ra, &secret_for_server)
        })
        .await;

        let bridge = AuthBridge::spawn(
            &Handle::current(),
            "127.0.0.1:0".parse().unwrap(),
            vec![(server_addr, secret)],
        )
        .await
        .expect("spawn bridge");

        let verdict = bridge
            .submit_pap(
                "alice".into(),
                b"pw".to_vec(),
                "127.0.0.1:5000".parse().unwrap(),
                None,
            )
            .await;
        match verdict {
            AuthVerdict::Reject { message } => {
                assert_eq!(&message, b"bad password");
            }
            AuthVerdict::Accept { .. } => panic!("expected Reject"),
        }
    }
}
