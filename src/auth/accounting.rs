//! RFC 2866 Accounting client.
//!
//! Drives `Accounting-Request` (code 4) → `Accounting-Response`
//! (code 5) over UDP. Unlike `Access-Request`, the Accounting
//! Request Authenticator is `MD5(code | id | length | 16 zero | attrs
//! | secret)` rather than random — this module uses
//! [`PacketBuffer::seal_as_zeroed_request`] for that construction.
//!
//! Byte counters and session duration are passed in by the caller;
//! the kernel maintains the actual counters on the `pppN` netdev
//! (see `ip -s link show pppN`, or `IFLA_STATS64` via netlink) and
//! we sample them at Interim/Stop emission time.
//!
//! Retry follows RFC 5080 §2.2.1 style — exponential backoff, capped
//! at a small number of attempts — and is independent per
//! `(server_addr, identifier)` correlation slot.

// M4 wire-up in progress: the transport, packet build/verify
// helpers, and per-session state are landed; integration from the
// session task (Start on NetworkUp, periodic Interim, Stop on
// teardown) lands alongside the [`crate::auth::AcctBridge`] facade.
// Once that's wired the blanket `dead_code` allow comes off.
#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use radius_tokio::{
    Code, CodecError, PacketBuffer, authenticator,
    dict::rfc::{
        self,
        values::{AcctAuthentic, AcctStatusType, AcctTerminateCause, FramedProtocol, NasPortType, ServiceType},
    },
};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, oneshot};
use tokio::time::timeout;

use crate::auth::request::AccessRequestCtx;

/// What kind of accounting record to emit.
#[derive(Debug, Clone, Copy)]
pub enum AcctEvent {
    /// Session bring-up, immediately after IPCP converges.
    Start,
    /// Periodic update; `session_time` is seconds since Start.
    InterimUpdate,
    /// Session teardown.
    Stop(AcctTerminateCause),
}

impl AcctEvent {
    fn status_type(self) -> AcctStatusType {
        match self {
            AcctEvent::Start => AcctStatusType::START,
            AcctEvent::InterimUpdate => AcctStatusType::INTERIM_UPDATE,
            AcctEvent::Stop(_) => AcctStatusType::STOP,
        }
    }
}

/// How a session ended, expressed in terms a RADIUS authenticator
/// can act on. Wider than [`crate::session::DisconnectReason`] (which
/// is just the cross-worker control-channel subset) — we also cover
/// the natural-completion paths the session task observes directly:
/// peer-initiated PPP teardown, transport loss, and authenticator
/// rejection.
///
/// Mapping to RFC 2866 §5.10 `Acct-Terminate-Cause` follows the
/// FreeRADIUS / accel-ppp convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// Peer requested teardown (LCP `Terminate-Request`, SSTP
    /// `Call-Disconnect`).
    UserRequest,
    /// TCP / TLS EOF, read/write error, or IPCP failure mid-session.
    LostCarrier,
    /// Per-session idle timer (PPP echo loss).
    IdleTimeout,
    /// Operator action via control socket (`disable session`).
    AdminReset,
    /// Process-wide drain in progress (SIGTERM, `shutdown`).
    NasReboot,
    /// Authenticator-side error during initial auth.
    NasError,
    /// Service unavailable (e.g. RADIUS unreachable).
    ServiceUnavailable,
}

impl SessionEnd {
    /// Project to a RADIUS `Acct-Terminate-Cause`.
    #[must_use]
    pub fn to_terminate_cause(self) -> AcctTerminateCause {
        match self {
            SessionEnd::UserRequest => AcctTerminateCause::USER_REQUEST,
            SessionEnd::LostCarrier => AcctTerminateCause::LOST_CARRIER,
            SessionEnd::IdleTimeout => AcctTerminateCause::IDLE_TIMEOUT,
            SessionEnd::AdminReset => AcctTerminateCause::ADMIN_RESET,
            SessionEnd::NasReboot => AcctTerminateCause::NAS_REBOOT,
            SessionEnd::NasError => AcctTerminateCause::NAS_ERROR,
            SessionEnd::ServiceUnavailable => AcctTerminateCause::SERVICE_UNAVAILABLE,
        }
    }
}

impl From<crate::session::DisconnectReason> for SessionEnd {
    fn from(reason: crate::session::DisconnectReason) -> Self {
        use crate::session::DisconnectReason as D;
        // Both `AdminRequested` (control socket) and `RadiusDisconnect`
        // (RFC 5176 CoA) are administrative actions from the user's
        // perspective; RFC 2866 §5.10 has no separate code for the
        // RADIUS-driven path, so they collapse onto `Admin-Reset`.
        #[allow(clippy::match_same_arms)]
        match reason {
            D::AdminRequested => SessionEnd::AdminReset,
            D::RadiusDisconnect => SessionEnd::AdminReset,
            D::ServerShutdown => SessionEnd::NasReboot,
        }
    }
}

/// Per-session accounting payload that *changes* between records.
/// (Identifying fields such as `Acct-Session-Id` and `User-Name`
/// live in [`AccessRequestCtx`] and the [`AcctSession`].)
#[derive(Debug, Clone, Default)]
pub struct AcctCounters {
    /// `Acct-Session-Time` (seconds since Start).
    pub session_time: u32,
    /// `Acct-Input-Octets` (bytes received from peer).
    pub input_octets: u64,
    /// `Acct-Output-Octets` (bytes sent to peer).
    pub output_octets: u64,
    /// `Acct-Input-Packets`.
    pub input_packets: u32,
    /// `Acct-Output-Packets`.
    pub output_packets: u32,
}

/// Identifying fields constant across a session's lifetime.
#[derive(Debug, Clone)]
pub struct AcctSession {
    /// `Acct-Session-Id` (RFC 2866 §5.5) — unique to this session
    /// on this NAS. Typically the lower 64 bits of session start
    /// time hex-encoded, but the value is opaque.
    pub session_id: String,
    /// `Acct-Authentic` (RFC 2866 §5.6) — how the user was
    /// authenticated. Defaults to `RADIUS`.
    pub authentic: AcctAuthentic,
    /// `Framed-IP-Address` (RFC 2865 §5.8) — the IPv4 the
    /// authenticator handed out and we assigned to `pppN` / `tun0`.
    /// Echoed in every accounting record for correlation.
    pub framed_ip: Ipv4Addr,
    /// `NAS-IP-Address` (RFC 2865 §5.4) — IPv4 of the local
    /// interface the SSTP listener accepted on, when available.
    /// Some deployments prefer the symbolic `NAS-Identifier` only;
    /// the two attributes are independent and may both appear.
    pub nas_ip: Option<Ipv4Addr>,
    /// `NAS-Port` (RFC 2865 §5.5) — 32-bit virtual port number
    /// uniquely identifying the session on this NAS. We use the
    /// per-process session id, which is monotonically allocated.
    pub nas_port: u32,
}

impl AcctSession {
    /// Synthesise a session-id from the current monotonic time.
    /// Callers with a better identifier (e.g. SSTP correlation ID)
    /// should construct the struct directly.
    #[must_use]
    pub fn new(framed_ip: Ipv4Addr, nas_port: u32) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        Self {
            session_id: format!("{nanos:016x}"),
            authentic: AcctAuthentic(1), // RADIUS
            framed_ip,
            nas_ip: None,
            nas_port,
        }
    }
}

/// Errors emitted by the accounting client.
#[derive(Debug, thiserror::Error)]
pub enum AcctError {
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("codec: {0}")]
    Codec(#[from] CodecError),
    #[error("no Accounting-Response within retry budget")]
    Timeout,
    #[error("identifier space exhausted for {0}")]
    IdentifierExhausted(SocketAddr),
    #[error("Accounting-Response authenticator mismatch")]
    AuthenticatorMismatch,
    #[error("unexpected reply code: {0:?}")]
    UnexpectedReply(Code),
    #[error("reader task dropped reply")]
    Cancelled,
}

/// Retry envelope for accounting transactions. Defaults are
/// RFC 5080 §2.2.1 conservative: 1s initial, ×2 backoff, 5 tries.
#[derive(Debug, Clone, Copy)]
pub struct AcctRetry {
    pub initial_timeout: Duration,
    pub max_attempts: u32,
    pub backoff_multiplier: u32,
}

impl Default for AcctRetry {
    fn default() -> Self {
        Self {
            initial_timeout: Duration::from_secs(1),
            max_attempts: 5,
            backoff_multiplier: 2,
        }
    }
}

#[derive(Default)]
struct PeerState {
    next_id: u8,
    inflight: HashMap<u8, oneshot::Sender<Vec<u8>>>,
}

impl PeerState {
    fn allocate(&mut self) -> Option<u8> {
        // Linear scan of the 256-slot space starting from next_id.
        // Production load lives at <<1% utilisation per peer so the
        // worst case is fine.
        for _ in 0..=u8::MAX {
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            if !self.inflight.contains_key(&id) {
                return Some(id);
            }
        }
        None
    }
}

/// Accounting client. Owns a single UDP socket and demuxes replies
/// across multiple peers by `(peer_addr, identifier)`.
pub struct AcctClient {
    socket: Arc<UdpSocket>,
    state: Arc<Mutex<HashMap<SocketAddr, PeerState>>>,
    retry: AcctRetry,
    reader: tokio::task::JoinHandle<()>,
}

impl AcctClient {
    /// Bind a UDP socket on `local_addr` (use `0.0.0.0:0` or
    /// `[::]:0` to let the kernel pick a source port) and start the
    /// reader task.
    pub async fn bind(local_addr: SocketAddr) -> std::io::Result<Self> {
        Self::bind_with(local_addr, AcctRetry::default()).await
    }

    pub async fn bind_with(local_addr: SocketAddr, retry: AcctRetry) -> std::io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(local_addr).await?);
        let state: Arc<Mutex<HashMap<SocketAddr, PeerState>>> = Arc::default();
        let reader = tokio::spawn(reader_loop(Arc::clone(&socket), Arc::clone(&state)));
        Ok(Self {
            socket,
            state,
            retry,
            reader,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Send one accounting record and await `Accounting-Response`.
    pub async fn send(
        &self,
        peer: SocketAddr,
        secret: &[u8],
        ctx: &AccessRequestCtx<'_>,
        session: &AcctSession,
        event: AcctEvent,
        counters: &AcctCounters,
    ) -> Result<(), AcctError> {
        let (identifier, reply_rx) = {
            let mut all = self.state.lock().await;
            let slot = all.entry(peer).or_default();
            let id = slot
                .allocate()
                .ok_or(AcctError::IdentifierExhausted(peer))?;
            let (tx, rx) = oneshot::channel();
            slot.inflight.insert(id, tx);
            (id, rx)
        };

        let result = self
            .send_inner(
                peer, secret, identifier, ctx, session, event, counters, reply_rx,
            )
            .await;

        // Reclaim slot regardless of outcome.
        let mut all = self.state.lock().await;
        if let Some(slot) = all.get_mut(&peer) {
            slot.inflight.remove(&identifier);
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_inner(
        &self,
        peer: SocketAddr,
        secret: &[u8],
        identifier: u8,
        ctx: &AccessRequestCtx<'_>,
        session: &AcctSession,
        event: AcctEvent,
        counters: &AcctCounters,
        mut reply_rx: oneshot::Receiver<Vec<u8>>,
    ) -> Result<(), AcctError> {
        // Anchor for `Acct-Delay-Time` (RFC 2866 §5.2). The first
        // send carries delay = 0; each retry rebuilds the packet so
        // the field reflects the elapsed wait. Rebuilding is cheap
        // (a few hundred bytes) and gives the authenticator an
        // accurate "how long has this event been buffered" hint.
        let started = Instant::now();
        let mut wait = self.retry.initial_timeout;
        let attempts = self.retry.max_attempts.max(1);
        for attempt in 0..attempts {
            let delay_secs = u32::try_from(started.elapsed().as_secs()).unwrap_or(u32::MAX);
            let bytes = build(identifier, secret, ctx, session, event, counters, delay_secs)?;
            self.socket.send_to(&bytes, peer).await?;
            match timeout(wait, &mut reply_rx).await {
                Ok(Ok(reply)) => {
                    return verify(&reply, secret, &request_authenticator_from(&bytes));
                }
                Ok(Err(_)) => return Err(AcctError::Cancelled),
                Err(_) => {
                    if attempt + 1 < attempts {
                        wait = wait.saturating_mul(self.retry.backoff_multiplier.max(1));
                    }
                }
            }
        }
        Err(AcctError::Timeout)
    }
}

impl Drop for AcctClient {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

async fn reader_loop(socket: Arc<UdpSocket>, state: Arc<Mutex<HashMap<SocketAddr, PeerState>>>) {
    let mut buf = [0u8; 4096];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, peer)) if n >= 20 => {
                let datagram = buf[..n].to_vec();
                let id = datagram[1];
                let waiter = {
                    let mut all = state.lock().await;
                    all.get_mut(&peer).and_then(|s| s.inflight.remove(&id))
                };
                if let Some(tx) = waiter {
                    // Receiver may have given up; ignore.
                    let _ = tx.send(datagram);
                }
            }
            Ok(_) => { /* short datagram; drop silently */ }
            Err(_) => break,
        }
    }
}

fn build(
    identifier: u8,
    secret: &[u8],
    ctx: &AccessRequestCtx<'_>,
    session: &AcctSession,
    event: AcctEvent,
    counters: &AcctCounters,
    delay_secs: u32,
) -> Result<Vec<u8>, AcctError> {
    let mut buf = PacketBuffer::new(Code::ACCOUNTING_REQUEST, identifier);
    buf.add(rfc::attrs::USER_NAME, ctx.username)?;
    if let Some(nas_ip) = session.nas_ip {
        buf.add(rfc::attrs::NAS_IP_ADDRESS, nas_ip)?;
    }
    if let Some(nid) = ctx.nas_identifier {
        buf.add(rfc::attrs::NAS_IDENTIFIER, nid)?;
    }
    buf.add(rfc::attrs::NAS_PORT, session.nas_port)?;
    buf.add(rfc::attrs::NAS_PORT_TYPE, NasPortType::VIRTUAL)?;
    buf.add(rfc::attrs::SERVICE_TYPE, ServiceType::FRAMED_USER)?;
    buf.add(rfc::attrs::FRAMED_PROTOCOL, FramedProtocol::PPP)?;
    buf.add(rfc::attrs::FRAMED_IP_ADDRESS, session.framed_ip)?;
    if let Some(csid) = ctx.calling_station_id {
        buf.add(rfc::attrs::CALLING_STATION_ID, csid)?;
    }
    buf.add(rfc::attrs::ACCT_STATUS_TYPE, event.status_type())?;
    buf.add(rfc::attrs::ACCT_AUTHENTIC, session.authentic)?;
    buf.add(rfc::attrs::ACCT_SESSION_ID, session.session_id.as_str())?;
    if delay_secs != 0 {
        buf.add(rfc::attrs::ACCT_DELAY_TIME, delay_secs)?;
    }

    // RFC 2866 §5.7: Acct-Session-Time MUST NOT appear on Start.
    if !matches!(event, AcctEvent::Start) {
        buf.add(rfc::attrs::ACCT_SESSION_TIME, counters.session_time)?;
        // Octet counters are 32-bit; the high 32 bits travel in the
        // Acct-{Input,Output}-Gigawords companion attributes
        // (RFC 2869 §5.1, §5.2). Emit the Gigaword attribute only
        // when the high half is non-zero so we don't pad every
        // packet with zeros.
        #[allow(clippy::cast_possible_truncation)]
        let in_lo = counters.input_octets as u32;
        #[allow(clippy::cast_possible_truncation)]
        let out_lo = counters.output_octets as u32;
        let in_hi = u32::try_from(counters.input_octets >> 32).unwrap_or(u32::MAX);
        let out_hi = u32::try_from(counters.output_octets >> 32).unwrap_or(u32::MAX);
        buf.add(rfc::attrs::ACCT_INPUT_OCTETS, in_lo)?;
        buf.add(rfc::attrs::ACCT_OUTPUT_OCTETS, out_lo)?;
        if in_hi != 0 {
            buf.add(rfc::attrs::ACCT_INPUT_GIGAWORDS, in_hi)?;
        }
        if out_hi != 0 {
            buf.add(rfc::attrs::ACCT_OUTPUT_GIGAWORDS, out_hi)?;
        }
        buf.add(rfc::attrs::ACCT_INPUT_PACKETS, counters.input_packets)?;
        buf.add(rfc::attrs::ACCT_OUTPUT_PACKETS, counters.output_packets)?;
    }

    if let AcctEvent::Stop(cause) = event {
        buf.add(rfc::attrs::ACCT_TERMINATE_CAUSE, cause)?;
    }

    let sealed = buf.seal_as_zeroed_request(secret);
    Ok(sealed.as_bytes().to_vec())
}

fn request_authenticator_from(bytes: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes[4..20]);
    out
}

fn verify(reply: &[u8], secret: &[u8], request_authenticator: &[u8; 16]) -> Result<(), AcctError> {
    if reply.len() < 20 {
        return Err(AcctError::AuthenticatorMismatch);
    }
    let code = Code(reply[0]);
    if code != Code::ACCOUNTING_RESPONSE {
        return Err(AcctError::UnexpectedReply(code));
    }
    if !authenticator::verify_response(reply, request_authenticator, secret) {
        return Err(AcctError::AuthenticatorMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> AccessRequestCtx<'static> {
        AccessRequestCtx {
            username: "alice",
            calling_station_id: Some("198.51.100.5:443"),
            nas_identifier: Some("sstp-test"),
        }
    }

    fn session() -> AcctSession {
        AcctSession {
            session_id: "deadbeefcafebabe".into(),
            authentic: AcctAuthentic(1),
            framed_ip: Ipv4Addr::new(10, 99, 0, 42),
            nas_ip: Some(Ipv4Addr::new(10, 0, 0, 1)),
            nas_port: 0xdead_beef,
        }
    }

    #[test]
    fn start_packet_shape() {
        let secret = b"sssh";
        let bytes = build(
            7,
            secret,
            &ctx(),
            &session(),
            AcctEvent::Start,
            &AcctCounters::default(),
            0,
        )
        .expect("build");
        assert_eq!(bytes[0], 4, "Accounting-Request");
        assert_eq!(bytes[1], 7);

        // Verify the zeroed-RA construction round-trips.
        let mut probe = bytes.clone();
        let mut sent_auth = [0u8; 16];
        sent_auth.copy_from_slice(&probe[4..20]);
        probe[4..20].copy_from_slice(&[0u8; 16]);
        let want = authenticator::compute_zeroed_request(&probe, secret);
        assert_eq!(sent_auth, want);

        // Start MUST NOT carry Acct-Session-Time and MUST carry the
        // identifying / framing attributes.
        let mut saw_nas_ip = false;
        let mut saw_framed_ip = false;
        let mut saw_service_type = false;
        let mut saw_framed_proto = false;
        let mut saw_nas_port_type = false;
        for raw in radius_tokio::attributes::iter(&bytes[20..]).filter_map(Result::ok) {
            assert_ne!(raw.attribute_type(), rfc::attrs::ACCT_SESSION_TIME.code);
            assert_ne!(raw.attribute_type(), rfc::attrs::ACCT_DELAY_TIME.code);
            match raw.attribute_type() {
                4 => saw_nas_ip = true,
                8 => saw_framed_ip = true,
                6 => saw_service_type = true,
                7 => saw_framed_proto = true,
                61 => saw_nas_port_type = true,
                _ => {}
            }
        }
        assert!(saw_nas_ip && saw_framed_ip && saw_service_type && saw_framed_proto && saw_nas_port_type);
    }

    #[test]
    fn stop_carries_terminate_cause_and_counters() {
        let secret = b"sssh";
        let counters = AcctCounters {
            session_time: 600,
            input_octets: 12_345,
            output_octets: 67_890,
            input_packets: 100,
            output_packets: 200,
        };
        let bytes = build(
            9,
            secret,
            &ctx(),
            &session(),
            AcctEvent::Stop(AcctTerminateCause::USER_REQUEST),
            &counters,
            0,
        )
        .expect("build");

        let mut saw_status = false;
        let mut saw_cause = false;
        let mut saw_time = false;
        let mut saw_in_giga = false;
        let mut saw_out_giga = false;
        for raw in radius_tokio::attributes::iter(&bytes[20..]).filter_map(Result::ok) {
            match raw.attribute_type() {
                40 => {
                    saw_status = true;
                    assert_eq!(raw.value(), 2u32.to_be_bytes());
                }
                49 => {
                    saw_cause = true;
                    assert_eq!(raw.value(), 1u32.to_be_bytes());
                }
                46 => {
                    saw_time = true;
                    assert_eq!(raw.value(), 600u32.to_be_bytes());
                }
                52 => saw_in_giga = true,
                53 => saw_out_giga = true,
                _ => {}
            }
        }
        assert!(saw_status && saw_cause && saw_time);
        // Counters under 4 GiB → no Gigawords companion attrs.
        assert!(!saw_in_giga && !saw_out_giga);
    }

    #[test]
    fn gigawords_emitted_when_high32_nonzero() {
        let counters = AcctCounters {
            session_time: 86_400,
            input_octets: (3u64 << 32) | 7, // 3 Gigawords + 7 octets
            output_octets: (5u64 << 32) | 11,
            input_packets: 0,
            output_packets: 0,
        };
        let bytes = build(
            1,
            b"sssh",
            &ctx(),
            &session(),
            AcctEvent::InterimUpdate,
            &counters,
            0,
        )
        .expect("build");
        let mut in_giga = None;
        let mut out_giga = None;
        let mut in_oct = None;
        let mut out_oct = None;
        for raw in radius_tokio::attributes::iter(&bytes[20..]).filter_map(Result::ok) {
            match raw.attribute_type() {
                42 => in_oct = Some(u32::from_be_bytes(raw.value().try_into().unwrap())),
                43 => out_oct = Some(u32::from_be_bytes(raw.value().try_into().unwrap())),
                52 => in_giga = Some(u32::from_be_bytes(raw.value().try_into().unwrap())),
                53 => out_giga = Some(u32::from_be_bytes(raw.value().try_into().unwrap())),
                _ => {}
            }
        }
        assert_eq!(in_oct, Some(7));
        assert_eq!(out_oct, Some(11));
        assert_eq!(in_giga, Some(3));
        assert_eq!(out_giga, Some(5));
    }

    #[test]
    fn delay_time_emitted_only_when_nonzero() {
        let bytes_zero = build(
            1,
            b"sssh",
            &ctx(),
            &session(),
            AcctEvent::Start,
            &AcctCounters::default(),
            0,
        )
        .expect("build");
        let bytes_delayed = build(
            2,
            b"sssh",
            &ctx(),
            &session(),
            AcctEvent::Start,
            &AcctCounters::default(),
            5,
        )
        .expect("build");
        let saw_delay = |bytes: &[u8]| {
            radius_tokio::attributes::iter(&bytes[20..])
                .filter_map(Result::ok)
                .any(|a| a.attribute_type() == rfc::attrs::ACCT_DELAY_TIME.code)
        };
        assert!(!saw_delay(&bytes_zero));
        assert!(saw_delay(&bytes_delayed));
    }

    #[test]
    fn session_end_maps_to_terminate_cause() {
        use crate::session::DisconnectReason;
        assert_eq!(
            SessionEnd::UserRequest.to_terminate_cause(),
            AcctTerminateCause::USER_REQUEST
        );
        assert_eq!(
            SessionEnd::LostCarrier.to_terminate_cause(),
            AcctTerminateCause::LOST_CARRIER
        );
        assert_eq!(
            SessionEnd::from(DisconnectReason::AdminRequested),
            SessionEnd::AdminReset
        );
        assert_eq!(
            SessionEnd::from(DisconnectReason::RadiusDisconnect),
            SessionEnd::AdminReset
        );
        assert_eq!(
            SessionEnd::from(DisconnectReason::ServerShutdown),
            SessionEnd::NasReboot
        );
    }

    #[tokio::test]
    async fn round_trip_against_one_shot_responder() {
        let secret = b"sssh".to_vec();
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let server_addr = server.local_addr().expect("addr");
        let secret_srv = secret.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (n, src) = server.recv_from(&mut buf).await.expect("recv");
            let req = &buf[..n];
            // Build minimal Accounting-Response: code 5, same id,
            // length 20, response authenticator over zeroed-attrs +
            // secret.
            let mut reply = vec![0u8; 20];
            reply[0] = 5;
            reply[1] = req[1];
            reply[2..4].copy_from_slice(&20u16.to_be_bytes());
            let mut req_auth = [0u8; 16];
            req_auth.copy_from_slice(&req[4..20]);
            // Response Auth = MD5(code|id|len|req_auth|attrs|secret).
            let mut to_hash = Vec::with_capacity(20 + secret_srv.len());
            to_hash.extend_from_slice(&reply[..4]);
            to_hash.extend_from_slice(&req_auth);
            to_hash.extend_from_slice(&secret_srv);
            let digest = crate::crypto::hash::Md5::digest(&to_hash);
            reply[4..20].copy_from_slice(&digest);
            server.send_to(&reply, src).await.expect("send");
        });

        let client = AcctClient::bind("127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind client");
        client
            .send(
                server_addr,
                &secret,
                &ctx(),
                &session(),
                AcctEvent::Start,
                &AcctCounters::default(),
            )
            .await
            .expect("accounting round-trip");
    }
}
