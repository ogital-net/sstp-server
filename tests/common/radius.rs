//! Dummy RADIUS authenticator used by the end-to-end tests.
//!
//! Built on `radius_tokio::server`. Accepts a single static credential
//! and replies with `Access-Accept` carrying a `Framed-IP-Address`;
//! every other user maps to `Access-Reject`. Records every inbound
//! request in a [`std::sync::Mutex`] so tests can assert "RADIUS was
//! reached" or "RADIUS saw this user-name".
//!
//! Bound to `127.0.0.1:<ephemeral>`, shutdown via the cloneable
//! [`ShutdownHandle`] returned alongside the server task. The
//! shared-secret defaults to `"testing123"` (matches
//! FreeRADIUS's documentation examples).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use radius_tokio::auth::{self, VerifyOutcome};
use radius_tokio::dict::rfc::attrs;
use radius_tokio::server::{
    Client, Handler, HandlerResult, IpCidr, Request, Server, ShutdownHandle, StaticClients,
};
use radius_tokio::{AttributesView, Code};
use tokio::task::JoinHandle;

/// Re-exported for tests so they can match against `pap_outcome`
/// without depending on `radius_tokio` directly.
pub use radius_tokio::auth::VerifyOutcome as PapOutcome;

pub const DEFAULT_SECRET: &[u8] = b"testing123";

/// Captured information about one inbound request. Kept narrow on
/// purpose — tests should assert presence / username, not iterate
/// every attribute.
#[derive(Debug, Clone)]
pub struct SeenRequest {
    pub code: Code,
    pub identifier: u8,
    pub src: SocketAddr,
    pub username: Option<String>,
    /// `Match` / `Mismatch` / `Missing` / `Malformed` from the PAP
    /// verifier. `None` when this wasn't an Access-Request or no
    /// `User-Password` attribute was present.
    pub pap_outcome: Option<VerifyOutcome>,
}

/// Static credential table used by the handler.
#[derive(Clone, Debug)]
pub struct Credential {
    pub username: String,
    pub password: Vec<u8>,
    pub framed_ip: Ipv4Addr,
    /// Optional `Framed-MTU` (RFC 2865 §5.12) sent on Access-Accept.
    pub framed_mtu: Option<u32>,
    /// Optional `Mikrotik-Rate-Limit` VSA (vendor 14988, attr 8)
    /// sent on Access-Accept; verbatim wire string,
    /// e.g. `"1M/2M"` (rx/tx, client-POV).
    pub mikrotik_rate_limit: Option<String>,
}

/// Handler that PAP-verifies against a single allowlisted credential.
struct PapHandler {
    credential: Credential,
    seen: Arc<Mutex<Vec<SeenRequest>>>,
}

impl Handler for PapHandler {
    async fn handle(&self, request: Request<'_>) -> HandlerResult {
        let username = request
            .first_raw(1)
            .ok()
            .flatten()
            .map(|raw| String::from_utf8_lossy(raw.value()).into_owned());

        let pap_outcome = if request.code() == Code::ACCESS_REQUEST {
            auth::pap::verify(&request, &self.credential.password).ok()
        } else {
            None
        };

        self.seen
            .lock()
            .expect("seen mutex poisoned")
            .push(SeenRequest {
                code: request.code(),
                identifier: request.identifier(),
                src: request.src(),
                username: username.clone(),
                pap_outcome,
            });

        // Non-Access-Request codes (Accounting, CoA) get a silent drop
        // — the test harness doesn't exercise them.
        if request.code() != Code::ACCESS_REQUEST {
            return HandlerResult::Drop;
        }

        let accept = matches!(pap_outcome, Some(VerifyOutcome::Match))
            && username.as_deref() == Some(self.credential.username.as_str());

        if accept {
            let mut reply = request.reply(Code::ACCESS_ACCEPT);
            // Framed-IP-Address (RFC 2865 §5.8). Required by the SSTP
            // server's RADIUS bridge — sessions without one are
            // rejected.
            if let Err(e) = reply.add(attrs::FRAMED_IP_ADDRESS, self.credential.framed_ip) {
                eprintln!("dummy-radius: failed to add Framed-IP-Address: {e:?}");
                return HandlerResult::Drop;
            }
            if let Some(mtu) = self.credential.framed_mtu
                && let Err(e) = reply.add(attrs::FRAMED_MTU, mtu)
            {
                eprintln!("dummy-radius: failed to add Framed-MTU: {e:?}");
                return HandlerResult::Drop;
            }
            if let Some(rl) = self.credential.mikrotik_rate_limit.as_deref() {
                use radius_tokio::typed::{VsaAttr, WText};
                if let Err(e) = reply.add_vsa(VsaAttr::<WText>::new(14988, 8), rl) {
                    eprintln!("dummy-radius: failed to add Mikrotik-Rate-Limit: {e:?}");
                    return HandlerResult::Drop;
                }
            }
            HandlerResult::Reply(reply)
        } else {
            HandlerResult::Reply(request.reply(Code::ACCESS_REJECT))
        }
    }
}

/// Running dummy RADIUS server. Drop it (or call
/// [`DummyRadius::shutdown`]) to terminate the listener task.
pub struct DummyRadius {
    pub addr: SocketAddr,
    pub secret: Vec<u8>,
    seen: Arc<Mutex<Vec<SeenRequest>>>,
    shutdown: ShutdownHandle,
    task: Option<JoinHandle<std::io::Result<()>>>,
}

impl DummyRadius {
    /// Start a server bound to a free `127.0.0.1` UDP port.
    pub async fn start(credential: Credential) -> Self {
        Self::start_with_secret(credential, DEFAULT_SECRET.to_vec()).await
    }

    pub async fn start_with_secret(credential: Credential, secret: Vec<u8>) -> Self {
        let bind: SocketAddr = "127.0.0.1:0".parse().expect("static parse");
        let client = Arc::new(Client::new(secret.as_slice()));
        let store = StaticClients::builder()
            .add(IpCidr::host(Ipv4Addr::LOCALHOST.into()), client)
            .build();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let handler = PapHandler {
            credential,
            seen: Arc::clone(&seen),
        };
        let server = Server::builder()
            .clients(store)
            .handler(handler)
            .listen_udp(bind)
            .build()
            .expect("build radius server");
        let shutdown = server.shutdown_handle();

        // Bind happens inside `server.run()`, so we need to surface the
        // actually-bound port before returning. The easiest reliable
        // way is to bind a UDP socket ourselves, read its port, drop
        // it, and hope the kernel doesn't reuse it before `serve_udp`
        // re-binds — but that's racy. Instead, we pre-bind a
        // throwaway UDP socket to pick a free port, then re-use that
        // port number for the server bind. Same race, smaller window.
        // For an integration test this is acceptable.
        //
        // FUTURE: when radius-tokio exposes the bound `SocketAddr`
        // back through ServerBuilder, we can drop this entirely.
        // For now we pick the port via [`crate::common::free_udp_port`]
        // *before* calling `start`, and pass it as the bind address.
        let task = tokio::spawn(server.run());

        // Give the listener task a brief window to bind. Tests that
        // race past this will get ECONNREFUSED and retry naturally.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        Self {
            addr: bind,
            secret,
            seen,
            shutdown,
            task: Some(task),
        }
    }

    /// Start a server on a caller-chosen port. Use this when the test
    /// needs to know the address before the server task starts (e.g.
    /// to pass it on the `sstp-server` command line).
    pub async fn start_on(port: u16, credential: Credential) -> Self {
        Self::start_on_with_secret(port, credential, DEFAULT_SECRET.to_vec()).await
    }

    pub async fn start_on_with_secret(port: u16, credential: Credential, secret: Vec<u8>) -> Self {
        let bind = SocketAddr::from(([127, 0, 0, 1], port));
        let client = Arc::new(Client::new(secret.as_slice()));
        let store = StaticClients::builder()
            .add(IpCidr::host(Ipv4Addr::LOCALHOST.into()), client)
            .build();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let handler = PapHandler {
            credential,
            seen: Arc::clone(&seen),
        };
        let server = Server::builder()
            .clients(store)
            .handler(handler)
            .listen_udp(bind)
            .build()
            .expect("build radius server");
        let shutdown = server.shutdown_handle();
        let task = tokio::spawn(server.run());

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        Self {
            addr: bind,
            secret,
            seen,
            shutdown,
            task: Some(task),
        }
    }

    /// Snapshot of every request the handler has seen so far.
    pub fn seen(&self) -> Vec<SeenRequest> {
        self.seen.lock().expect("seen mutex poisoned").clone()
    }

    pub fn shutdown(&self) {
        self.shutdown.shutdown();
    }
}

impl Drop for DummyRadius {
    fn drop(&mut self) {
        self.shutdown.shutdown();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
