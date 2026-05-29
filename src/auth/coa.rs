//! RFC 3576 / RFC 5176 CoA & Disconnect-Request receiver.
//!
//! Listens for `CoA-Request` (43) and `Disconnect-Request` (40)
//! from a trusted authenticator (typically the RADIUS server or a
//! sibling NAS-manager), authenticates the packet, dispatches the
//! decoded identifying attributes to a caller-supplied [`Handler`],
//! and emits the corresponding ACK / NAK reply.
//!
//! v0.1 scope is **identification + response only**: the handler
//! receives the parsed [`Identity`] (User-Name / Acct-Session-Id /
//! Calling-Station-Id triplet) and returns an [`Outcome`]. The
//! caller is responsible for translating an `Outcome::Ack` on a
//! Disconnect-Request into an actual session teardown — typically by
//! sending on an MPSC channel to the owning I/O worker. That wiring
//! lands with M6.
//!
//! Authentication: the Request Authenticator on CoA / Disconnect is
//! computed with the same zeroed-RA construction as accounting
//! (RFC 5176 §3.4), so we reuse
//! [`authenticator::compute_zeroed_request`]. We additionally
//! require Message-Authenticator (RFC 5080 §2.2.2 / `BlastRADIUS`
//! mitigation).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use radius_tokio::{
    Code, PacketBuffer, attributes, authenticator,
    dict::rfc,
    header::{Header, HeaderError},
    message_authenticator::{self, Verification},
};
use tokio::net::UdpSocket;
use tracing::{debug, trace};

/// Default port for the dynamic-authorization extension (RFC 5176 §2).
pub const DEFAULT_PORT: u16 = 3799;

/// Identifying attributes carried in a CoA / Disconnect request.
///
/// At least one of `username` or `acct_session_id` must be present
/// for the request to be actionable per RFC 5176 §3; a handler that
/// gets neither should return `Outcome::Nak(ErrorCause::MissingAttribute)`.
#[derive(Debug, Clone, Default)]
pub struct Identity {
    pub username: Option<String>,
    pub acct_session_id: Option<String>,
    pub calling_station_id: Option<String>,
    pub framed_ip: Option<std::net::Ipv4Addr>,
}

/// Subset of RFC 3576 §3.5 / RFC 5176 §3.5 Error-Cause values we
/// emit. Numbers match the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCause {
    ResidualSessionContextRemoved = 201,
    InvalidEapPacket = 202,
    UnsupportedAttribute = 401,
    MissingAttribute = 402,
    NasIdentificationMismatch = 403,
    InvalidRequest = 404,
    UnsupportedService = 405,
    UnsupportedExtension = 406,
    InvalidAttributeValue = 407,
    AdministrativelyProhibited = 501,
    RequestNotRoutable = 502,
    SessionContextNotFound = 503,
    SessionContextNotRemovable = 504,
    OtherProxyProcessingError = 505,
    ResourcesUnavailable = 506,
    RequestInitiated = 507,
}

/// What the handler wants done with an incoming request.
#[derive(Debug, Clone, Copy)]
pub enum Outcome {
    /// Send CoA-ACK / Disconnect-ACK.
    Ack,
    /// Send CoA-NAK / Disconnect-NAK with the supplied Error-Cause.
    Nak(ErrorCause),
}

/// Caller-supplied callback: classifies the request and decides the
/// reply. Until M6's session map exists, an implementation can
/// return `Outcome::Nak(ErrorCause::SessionContextNotFound)`
/// unconditionally and just log.
pub trait Handler: Send + Sync + 'static {
    fn handle(&self, kind: Code, peer: SocketAddr, identity: Identity) -> Outcome;
}

impl<F> Handler for F
where
    F: Fn(Code, SocketAddr, Identity) -> Outcome + Send + Sync + 'static,
{
    fn handle(&self, kind: Code, peer: SocketAddr, identity: Identity) -> Outcome {
        (self)(kind, peer, identity)
    }
}

/// Trust configuration: each peer that may send CoA/Disconnect
/// requests, plus its shared secret.
#[derive(Debug, Clone, Default)]
pub struct PeerSecrets {
    map: HashMap<IpAddr, Vec<u8>>,
}

impl PeerSecrets {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, peer: IpAddr, secret: Vec<u8>) {
        self.map.insert(peer, secret);
    }

    #[must_use]
    pub fn lookup(&self, peer: IpAddr) -> Option<&[u8]> {
        self.map.get(&peer).map(Vec::as_slice)
    }
}

/// CoA / Disconnect-Request listener.
pub struct CoaListener {
    socket: Arc<UdpSocket>,
    secrets: Arc<PeerSecrets>,
    handler: Arc<dyn Handler>,
}

impl CoaListener {
    /// Bind a UDP socket on `local_addr` (default port [`DEFAULT_PORT`]).
    pub async fn bind<H: Handler>(
        local_addr: SocketAddr,
        secrets: PeerSecrets,
        handler: H,
    ) -> std::io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(local_addr).await?);
        Ok(Self {
            socket,
            secrets: Arc::new(secrets),
            handler: Arc::new(handler),
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Drive the receive loop until the socket errors out.
    pub async fn run(self) -> std::io::Result<()> {
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, peer) = self.socket.recv_from(&mut buf).await?;
            if let Err(e) = self.process(&buf[..n], peer).await {
                debug!(?peer, error = %e, "coa: dropped request");
            }
        }
    }

    async fn process(&self, datagram: &[u8], peer: SocketAddr) -> Result<(), CoaDropReason> {
        let (header, attrs) = Header::parse(datagram).map_err(CoaDropReason::Header)?;
        if header.code != Code::COA_REQUEST && header.code != Code::DISCONNECT_REQUEST {
            return Err(CoaDropReason::UnexpectedCode(header.code));
        }

        let secret = self
            .secrets
            .lookup(peer.ip())
            .ok_or(CoaDropReason::UntrustedPeer)?;

        let want = authenticator::compute_zeroed_request(datagram, secret);
        if !radius_tokio::ct_eq(&want, &header.authenticator) {
            return Err(CoaDropReason::BadAuthenticator);
        }

        // Require Message-Authenticator on CoA/Disconnect (RFC 5080).
        // For these codes the sender computes the MA HMAC with the
        // Authenticator field set to 16 zero octets (the actual RA is
        // derived from the packet *including* the MA, so it can't
        // exist at MA-computation time). Verify with the same
        // convention.
        match message_authenticator::verify(datagram, &[0u8; 16], secret) {
            Verification::Valid => {}
            Verification::Absent => return Err(CoaDropReason::MissingMessageAuth),
            Verification::Invalid => return Err(CoaDropReason::BadMessageAuth),
        }

        let identity = decode_identity(attrs);
        trace!(?peer, code = ?header.code, ?identity, "coa: dispatching");

        let outcome = self.handler.handle(header.code, peer, identity);
        let reply = build_reply(
            header.code,
            header.identifier,
            outcome,
            &header.authenticator,
            secret,
        );
        self.socket.send_to(reply.as_bytes(), peer).await.ok();
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
enum CoaDropReason {
    #[error("header: {0:?}")]
    Header(HeaderError),
    #[error("unexpected code: {0:?}")]
    UnexpectedCode(Code),
    #[error("untrusted peer (no shared secret configured)")]
    UntrustedPeer,
    #[error("Request-Authenticator mismatch")]
    BadAuthenticator,
    #[error("missing Message-Authenticator")]
    MissingMessageAuth,
    #[error("Message-Authenticator mismatch")]
    BadMessageAuth,
}

fn decode_identity(attrs: &[u8]) -> Identity {
    let mut out = Identity::default();
    for raw in attributes::iter(attrs).filter_map(Result::ok) {
        match raw.attribute_type() {
            t if t == rfc::attrs::USER_NAME.code => {
                out.username = std::str::from_utf8(raw.value()).ok().map(str::to_owned);
            }
            t if t == rfc::attrs::ACCT_SESSION_ID.code => {
                out.acct_session_id = std::str::from_utf8(raw.value()).ok().map(str::to_owned);
            }
            t if t == rfc::attrs::CALLING_STATION_ID.code => {
                out.calling_station_id = std::str::from_utf8(raw.value()).ok().map(str::to_owned);
            }
            t if t == rfc::attrs::FRAMED_IP_ADDRESS.code => {
                if let Ok(arr) = <[u8; 4]>::try_from(raw.value()) {
                    out.framed_ip = Some(arr.into());
                }
            }
            _ => {}
        }
    }
    out
}

fn build_reply(
    request_code: Code,
    identifier: u8,
    outcome: Outcome,
    request_authenticator: &[u8; 16],
    secret: &[u8],
) -> PacketBuffer {
    let reply_code = match (request_code, outcome) {
        (Code::COA_REQUEST, Outcome::Ack) => Code::COA_ACK,
        (Code::COA_REQUEST, Outcome::Nak(_)) => Code::COA_NAK,
        (Code::DISCONNECT_REQUEST, Outcome::Ack) => Code::DISCONNECT_ACK,
        (Code::DISCONNECT_REQUEST, Outcome::Nak(_)) => Code::DISCONNECT_NAK,
        _ => unreachable!("validated in process()"),
    };

    let mut reply = radius_tokio::Reply::new(reply_code, identifier);
    if let Outcome::Nak(cause) = outcome {
        // Best-effort; an oversize attribute here is impossible (u32).
        reply
            .add(rfc::attrs::ERROR_CAUSE, cause as u32)
            .expect("ERROR_CAUSE fits in a fresh Reply");
    }
    reply.seal_for(request_authenticator, secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> Vec<u8> {
        b"sssh".to_vec()
    }

    /// Hand-build a CoA-Request with the zeroed-RA construction and a
    /// valid Message-Authenticator.
    fn build_coa_request(
        code: Code,
        identifier: u8,
        secret: &[u8],
        attrs: &[(u8, &[u8])],
    ) -> Vec<u8> {
        let mut buf = PacketBuffer::new(code, identifier);
        // MA placeholder first so its offset is known.
        message_authenticator::append_zeroed_slot(&mut buf).unwrap();
        for (typ, val) in attrs {
            buf.add_attribute(*typ, val).unwrap();
        }
        // Fill MA: HMAC-MD5(secret, packet-with-MA-zeroed).
        // append_zeroed_slot already left the value zeroed, and
        // seal_as_zeroed_request will overwrite the authenticator
        // afterwards. Order: seal MA over the packet with
        // authenticator=zero (which it is, since seal_as_zeroed_request
        // works on the zero RA), then compute the RA.
        // radius-tokio's seal_for handles the right ordering on the
        // *reply* path; for our test we need to do it by hand:
        // 1) compute MA over (header with code/id/len, zeroed RA,
        //    zeroed MA value, attributes), write into MA value;
        // 2) compute RA over (header, zeroed RA, attributes with MA
        //    now filled in), write into header.
        let bytes = buf.as_bytes();
        // PacketBuffer doesn't patch the length field until seal_*;
        // do it by hand so Header::parse sees the full attribute area.
        let mut bytes = bytes.to_vec();
        let len = u16::try_from(bytes.len()).unwrap();
        bytes[2..4].copy_from_slice(&len.to_be_bytes());
        // Step 1: MA over the bytes as-is (RA is zero, MA value is zero).
        let ma = hmac_md5(secret, &bytes);
        // Locate the MA slot: it's the first attribute, so type=80
        // sits at offset 20, length at 21, value starts at 22.
        let ma_value_offset = 22;
        bytes[ma_value_offset..ma_value_offset + 16].copy_from_slice(&ma);
        // Step 2: RA = MD5(code|id|len|zero-RA|attrs|secret).
        let ra = authenticator::compute_zeroed_request(&bytes, secret);
        bytes[4..20].copy_from_slice(&ra);
        bytes
    }

    fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
        use fast_md5::Md5;
        let block = 64;
        let mut k = if key.len() > block {
            fast_md5::digest(key).to_vec()
        } else {
            key.to_vec()
        };
        k.resize(block, 0);
        let mut ipad = vec![0x36u8; block];
        let mut opad = vec![0x5cu8; block];
        for i in 0..block {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }
        let mut inner = Md5::new();
        inner.update(&ipad);
        inner.update(data);
        let inner_digest = inner.finalize();
        let mut outer = Md5::new();
        outer.update(&opad);
        outer.update(&inner_digest);
        outer.finalize()
    }

    #[tokio::test]
    async fn disconnect_request_ack_round_trip() {
        let mut peers = PeerSecrets::new();
        peers.insert("127.0.0.1".parse().unwrap(), secret());

        let listener = CoaListener::bind(
            "127.0.0.1:0".parse().unwrap(),
            peers,
            |code: Code, _peer: SocketAddr, id: Identity| {
                assert_eq!(code, Code::DISCONNECT_REQUEST);
                assert_eq!(id.username.as_deref(), Some("alice"));
                Outcome::Ack
            },
        )
        .await
        .expect("bind");
        let listener_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.run().await;
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pkt = build_coa_request(
            Code::DISCONNECT_REQUEST,
            42,
            &secret(),
            &[(rfc::attrs::USER_NAME.code, b"alice")],
        );
        client.send_to(&pkt, listener_addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .expect("reply timeout")
        .expect("recv");
        assert_eq!(buf[0], Code::DISCONNECT_ACK.0);
        assert_eq!(buf[1], 42);

        // Reply Authenticator must verify against our request RA.
        let mut ra = [0u8; 16];
        ra.copy_from_slice(&pkt[4..20]);
        assert!(authenticator::verify_response(&buf[..n], &ra, &secret()));
    }

    #[tokio::test]
    async fn coa_request_nak_with_error_cause() {
        let mut peers = PeerSecrets::new();
        peers.insert("127.0.0.1".parse().unwrap(), secret());
        let listener = CoaListener::bind(
            "127.0.0.1:0".parse().unwrap(),
            peers,
            |_code: Code, _peer: SocketAddr, _id: Identity| {
                Outcome::Nak(ErrorCause::SessionContextNotFound)
            },
        )
        .await
        .unwrap();
        let listener_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.run().await;
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pkt = build_coa_request(
            Code::COA_REQUEST,
            7,
            &secret(),
            &[(rfc::attrs::ACCT_SESSION_ID.code, b"deadbeefcafebabe")],
        );
        client.send_to(&pkt, listener_addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(buf[0], Code::COA_NAK.0);
        // Find Error-Cause attribute (101).
        let mut found = false;
        for raw in attributes::iter(&buf[20..n]).filter_map(Result::ok) {
            if raw.attribute_type() == rfc::attrs::ERROR_CAUSE.code {
                assert_eq!(raw.value(), &503u32.to_be_bytes());
                found = true;
            }
        }
        assert!(found, "Error-Cause not present");
    }

    #[tokio::test]
    async fn bad_secret_drops_silently() {
        let mut peers = PeerSecrets::new();
        peers.insert("127.0.0.1".parse().unwrap(), secret());
        let listener = CoaListener::bind("127.0.0.1:0".parse().unwrap(), peers, |_, _, _| {
            panic!("handler must not run on bad-auth packet")
        })
        .await
        .unwrap();
        let listener_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.run().await;
        });

        // Sign with the wrong secret.
        let pkt = build_coa_request(
            Code::DISCONNECT_REQUEST,
            1,
            b"WRONG",
            &[(rfc::attrs::USER_NAME.code, b"alice")],
        );
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&pkt, listener_addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let res = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            client.recv_from(&mut buf),
        )
        .await;
        assert!(res.is_err(), "expected no reply for bad auth");
    }
}
