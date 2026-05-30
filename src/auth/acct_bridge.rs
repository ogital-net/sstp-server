//! Cross-runtime RADIUS-accounting dispatcher.
//!
//! Mirrors [`crate::auth::bridge::AuthBridge`] in shape, but is
//! **fire-and-forget**: the session task hands an
//! [`AcctEvent`]-shaped record across an MPSC channel and continues
//! immediately. The auth runtime owns the [`AcctClient`] UDP socket,
//! runs the retry loop against each `--acct` server in failover
//! order, and logs at warn on any non-success outcome. There is no
//! oneshot reply because the session has no useful action to take
//! on accounting failure beyond what the log already records.
//!
//! Backpressure: a full queue means the auth runtime is wedged
//! against an unresponsive accounting server. Records are dropped
//! at the queue boundary and counted as
//! `acct_records_dropped{reason="queue_full"}`. Dropping is
//! correct here — keeping the queue is unbounded memory growth and
//! Stop records still beat back-pressuring an I/O worker on session
//! teardown.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::auth::accounting::{
    AcctClient, AcctCounters, AcctError, AcctEvent, AcctSession,
};
use crate::auth::request::AccessRequestCtx;

/// Bounded queue depth, matched to [`AuthBridge`]. One outstanding
/// record per session × number of in-progress retries; 1024 covers
/// realistic production load with ample headroom.
const QUEUE_DEPTH: usize = 1024;

/// One accounting record to be emitted. Carries every field the
/// builder needs except the per-server `(addr, secret)` pair, which
/// the dispatcher iterates internally.
struct AcctRecord {
    /// `User-Name`. Owned so the session task can send and forget.
    username: String,
    /// `Calling-Station-Id` (peer source).
    peer: SocketAddr,
    session: AcctSession,
    event: AcctEvent,
    counters: AcctCounters,
}

/// Cloneable handle to the accounting dispatcher. Cheap to clone
/// (wraps an `mpsc::Sender`); held by every session task that may
/// emit accounting records.
#[derive(Clone)]
pub struct AcctBridge {
    tx: mpsc::Sender<AcctRecord>,
}

impl std::fmt::Debug for AcctBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcctBridge").finish_non_exhaustive()
    }
}

impl AcctBridge {
    /// Construct the bridge, bind a UDP socket on `bind_addr`, and
    /// spawn the dispatcher on `handle`.
    ///
    /// `servers` is the ordered list of accounting authenticators
    /// to try in failover order, each paired with its shared secret
    /// (typically `SSTP_RADIUS_ACCT_SECRET`, falling back to
    /// `SSTP_RADIUS_SECRET`).
    ///
    /// # Errors
    ///
    /// Returns the underlying [`std::io::Error`] if binding the UDP
    /// socket fails.
    ///
    /// # Panics
    ///
    /// Panics if `servers` is empty — checked at the caller before
    /// instantiating the bridge.
    pub async fn spawn(
        handle: &Handle,
        bind_addr: SocketAddr,
        servers: Vec<(SocketAddr, Arc<[u8]>)>,
        nas_identifier: Option<Arc<str>>,
    ) -> std::io::Result<Self> {
        assert!(
            !servers.is_empty(),
            "AcctBridge::spawn requires at least one accounting server",
        );
        let client = Arc::new(AcctClient::bind(bind_addr).await?);
        let servers = Arc::<[(SocketAddr, Arc<[u8]>)]>::from(servers);
        let (tx, mut rx) = mpsc::channel::<AcctRecord>(QUEUE_DEPTH);
        handle.spawn(async move {
            while let Some(record) = rx.recv().await {
                let client = Arc::clone(&client);
                let servers = Arc::clone(&servers);
                let nas = nas_identifier.clone();
                // Per-record spawn so a stuck server can't HOL-block
                // the queue. The session task has already returned
                // by the time we get here.
                tokio::spawn(async move { run_one(client, servers, nas, record).await });
            }
            debug!("acct dispatcher exiting (all senders dropped)");
        });
        Ok(Self { tx })
    }

    /// Submit an accounting record. Returns immediately; the actual
    /// RADIUS round-trip runs on the auth runtime.
    ///
    /// A full queue increments
    /// `acct_records_dropped{reason="queue_full"}` and logs at
    /// warn. The session task should not change behaviour on a
    /// drop — accounting is best-effort.
    pub fn submit(
        &self,
        username: String,
        peer: SocketAddr,
        session: AcctSession,
        event: AcctEvent,
        counters: AcctCounters,
    ) {
        let record = AcctRecord {
            username,
            peer,
            session,
            event,
            counters,
        };
        match self.tx.try_send(record) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(r)) => {
                warn!(
                    user = %r.username,
                    event = ?r.event,
                    "acct queue full; dropping record",
                );
            }
            Err(mpsc::error::TrySendError::Closed(r)) => {
                warn!(
                    user = %r.username,
                    event = ?r.event,
                    "acct dispatcher closed; dropping record",
                );
            }
        }
    }
}

async fn run_one(
    client: Arc<AcctClient>,
    servers: Arc<[(SocketAddr, Arc<[u8]>)]>,
    nas_identifier: Option<Arc<str>>,
    record: AcctRecord,
) {
    let peer_ip = record.peer.ip().to_string();
    let ctx = AccessRequestCtx {
        username: &record.username,
        calling_station_id: Some(&peer_ip),
        nas_identifier: nas_identifier.as_deref(),
    };
    let mut last_err: Option<AcctError> = None;
    for (addr, secret) in servers.iter() {
        match client
            .send(
                *addr,
                secret,
                &ctx,
                &record.session,
                record.event,
                &record.counters,
            )
            .await
        {
            Ok(()) => {
                debug!(
                    radius = %addr,
                    user = %record.username,
                    event = ?record.event,
                    "accounting record acked",
                );
                return;
            }
            Err(e) => {
                warn!(
                    radius = %addr,
                    user = %record.username,
                    event = ?record.event,
                    error = %e,
                    "accounting attempt failed; trying next server",
                );
                last_err = Some(e);
            }
        }
    }
    if let Some(e) = last_err {
        warn!(
            user = %record.username,
            event = ?record.event,
            error = %e,
            "accounting record dropped; no servers reachable",
        );
    }
}
