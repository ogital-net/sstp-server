//! PPP control-plane driver: LCP → auth → IPCP orchestration.
//!
//! Wraps the pure-logic [`super::fsm::Fsm`] with the server-side
//! option-negotiation policy for LCP ([RFC 1661] §6) and IPCP
//! ([RFC 1332] §3 + [RFC 1877]), plus the PAP authenticate path
//! ([RFC 1334] §2).
//!
//! Consumed by [`crate::session::drive_sstp`]. The driver is pure
//! logic: it takes inbound PPP frame bytes plus external events
//! (timer fire, auth backend reply) and emits a [`PppStep`] carrying
//! encoded outbound PPP frames, timer updates, and higher-layer
//! notifications.
//!
//! v0.1 scope is **PAP only** for authentication. CHAP / MS-CHAPv2 /
//! EAP plumbing exists in [`super::auth`] but is not yet wired through
//! the orchestrator; LCP advertises `Auth-Protocol = PAP` only.

use std::time::Duration;

use super::auth::{chap, pap};
use super::frame::{ADDRESS_ALL_STATIONS, CONTROL_UI, ProtocolId, decode_frame, encode_frame};
use super::fsm::{
    DEFAULT_RESTART, Event as FsmEvent, Fsm, RestartTimer, Send as FsmSend, StepOut as FsmStep,
};
use super::ipcp::{
    IPV4_OPTION_TOTAL_LEN, IpcpCode, IpcpOptionId, read_ipv4_value, write_ipv4_option,
};
use super::lcp::{
    ConfigOption, ConfigOptionIter, DEFAULT_MRU, LCP_HEADER_LEN, LCP_OPT_HEADER_LEN, LcpCode,
    LcpOptionId, LcpPacket, auth_protocol_chap_md5, auth_protocol_mschapv2, auth_protocol_pap,
    decode_lcp_packet, write_lcp_header, write_option,
};

/// Which sub-protocol's restart timer the [`PppStep`] is asking to
/// arm or stop. Both timers use [`DEFAULT_RESTART`] (3 s, RFC 1661
/// §4.1) but the session task tracks them in separate slots so a
/// concurrent LCP terminate + IPCP retransmit don't shadow each
/// other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerOwner {
    Lcp,
    Ipcp,
}

/// Drive a single FSM step and emit a `trace`-level log under
/// `sstp::ppp::fsm` when the transition crosses a state boundary.
/// The pure-logic [`Fsm`] type is intentionally tracing-free; this
/// wrapper is the single instrumentation point used by every
/// `LcpServer` / `IpcpServer` / [`Ppp`] call site.
fn step_traced(fsm: &mut Fsm, proto: &'static str, event: FsmEvent) -> FsmStep {
    let from = fsm.state();
    let out = fsm.step(event);
    if from != out.new_state {
        tracing::trace!(
            target: "sstp::ppp::fsm",
            proto,
            from = ?from,
            to = ?out.new_state,
            event = ?event,
            "PPP FSM transition"
        );
    }
    out
}

/// Result of one driver step: outbound frames already encoded with
/// Address/Control/Protocol (ready to be wrapped in an SSTP data
/// packet), timer ops, an optional higher-layer event, and a
/// `finished` flag that signals the session task to tear down.
#[derive(Debug, Default)]
pub struct PppStep {
    /// Encoded PPP frames (`encode_frame` output). Each entry is a
    /// complete frame including the leading 0xFF 0x03 + 2-byte
    /// Protocol; the caller wraps each one in an SSTP data packet.
    pub frames: Vec<Vec<u8>>,
    /// Timers to arm. Multiple owners may appear in one step (e.g.
    /// LCP Up triggers IPCP open which arms its restart timer).
    pub timer_starts: Vec<(TimerOwner, Duration)>,
    /// Timers to cancel.
    pub timer_stops: Vec<TimerOwner>,
    /// Higher-layer notification (at most one per step in practice;
    /// kept as `Option` so call sites can `if let Some(...)`).
    pub event: Option<PppEvent>,
    /// True when the PPP layer has reached a terminal state and the
    /// session should be closed. Set on LCP `tlf` (terminate
    /// acknowledged) or unrecoverable failure.
    pub finished: bool,
}

impl PppStep {
    fn push_frame(&mut self, frame: Vec<u8>) {
        self.frames.push(frame);
    }
}

/// Higher-layer event emitted by the PPP driver.
#[derive(Debug)]
pub enum PppEvent {
    /// Peer sent PAP `Authenticate-Request`; the session task must
    /// run RADIUS and feed the verdict back via
    /// [`Ppp::on_auth_result`].
    NeedPapAuth { peer_id: Vec<u8>, password: Vec<u8> },
    /// Peer sent CHAP-MD5 `Response`; the session task must run
    /// RADIUS and feed the verdict back via [`Ppp::on_auth_result`].
    /// The 16-byte response hash is forwarded as `CHAP-Password`;
    /// the `challenge` we originally sent goes as `CHAP-Challenge`.
    NeedChapAuth {
        username: Vec<u8>,
        chap_id: u8,
        challenge: [u8; 16],
        response: [u8; 16],
    },
    /// Peer sent an MS-CHAPv2 `Response`; the session task must run
    /// RADIUS and feed the verdict back via
    /// [`Ppp::on_mschap_result`] together with the
    /// `MS-CHAP2-Success` Authenticator-Response body the
    /// authenticator returned ([RFC 2759] §6 / RFC 2548 §2.3.3).
    NeedMsChapV2Auth {
        username: Vec<u8>,
        chap_id: u8,
        authenticator_challenge: [u8; 16],
        peer_challenge: [u8; 16],
        nt_response: [u8; 24],
        flags: u8,
    },
    /// IPCP converged: the kernel-PPP layer (M6g) can now bring the
    /// `pppN` interface up with the assigned addresses.
    NetworkUp(AssignedAddrs),
}

/// Addresses handed down by the auth backend and negotiated through
/// IPCP. Populated by M6e (`Framed-IP-Address`, `MS-Primary-DNS-Server`
/// etc. from the RADIUS Access-Accept).
#[derive(Debug, Default, Clone, Copy)]
pub struct AssignedAddrs {
    pub ip: [u8; 4],
    pub mtu: Option<u16>,
    pub dns1: Option<[u8; 4]>,
    pub dns2: Option<[u8; 4]>,
    pub nbns1: Option<[u8; 4]>,
    pub nbns2: Option<[u8; 4]>,
}

/// Verdict from RADIUS to apply to the in-progress PAP exchange.
#[derive(Debug)]
pub enum AuthVerdict {
    Accept { addrs: AssignedAddrs },
    Reject { message: Vec<u8> },
}

/// PPP authentication method advertised by the server in its LCP
/// `Configure-Request`. v0.1 supports PAP ([RFC 1334]), CHAP-MD5
/// ([RFC 1994]), and MS-CHAPv2 ([RFC 2759]); EAP pass-through
/// lands in a later milestone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthMethod {
    #[default]
    Pap,
    ChapMd5,
    MsChapV2,
}

// =============================================================================
//  LCP server
// =============================================================================

/// Server-side LCP driver. Owns the FSM, the in-flight CR identifier,
/// and a snapshot of the most recent inbound CR's option bytes so
/// that `Send::ConfigureAck` / `Send::ConfigureNak` actions can echo
/// the right payload.
struct LcpServer {
    fsm: Fsm,
    /// Identifier of the most recently received inbound CR. Used to
    /// stamp Configure-Ack / -Nak / -Reject responses.
    last_cr_id: u8,
    /// Echo body for `Send::ConfigureAck` (the inbound CR option
    /// list, verbatim).
    last_cr_options: Vec<u8>,
    /// Option list for `Send::ConfigureNak` — either Nak (recognised
    /// options with unacceptable values) or Reject (unknown options).
    /// Kept as a tagged blob the FSM hands back unchanged.
    pending_nak: Vec<u8>,
    pending_nak_is_reject: bool,
    /// State for the most recent inbound RXR-class packet
    /// (Echo-Request / Echo-Reply / Discard-Request, [RFC 1661]
    /// §5.8 / §5.9). The FSM lumps all three into `RcvEcho` and,
    /// in the Opened state, asks us to render an `EchoReply` —
    /// which is only correct when the inbound code was actually
    /// Echo-Request. We capture the inbound code, identifier, and
    /// data here so `render_lcp_send` can build the reply (and
    /// suppress it for Echo-Reply / Discard-Request).
    last_rxr_code: u8,
    last_echo_id: u8,
    last_echo_data: Vec<u8>,
    /// `True` once LCP Opened (i.e. `tlu` fired). Drives the
    /// session-level transition to the auth phase.
    opened: bool,
    /// Authentication method the server advertises in its outbound
    /// `Configure-Request`. PAP or CHAP-MD5 today.
    auth_method: AuthMethod,
    /// Most recent MRU advertised by the peer in an inbound LCP
    /// `Configure-Request` ([RFC 1661] §6.1). Captured during
    /// option classification and folded into the netdev MTU at
    /// `advance_to_network`. `None` until the peer sends a CR
    /// containing an MRU option.
    peer_mru: Option<u16>,
}

impl LcpServer {
    fn new(auth_method: AuthMethod) -> Self {
        Self {
            fsm: Fsm::new(),
            last_cr_id: 0,
            last_cr_options: Vec::new(),
            pending_nak: Vec::new(),
            pending_nak_is_reject: false,
            last_rxr_code: 0,
            last_echo_id: 0,
            last_echo_data: Vec::new(),
            opened: false,
            auth_method,
            peer_mru: None,
        }
    }

    /// Drive `Open` + `Up` to kick off the server's initial CR.
    /// Returns the FSM step result for the caller to render.
    fn open(&mut self) -> FsmStep {
        let _ = step_traced(&mut self.fsm, "lcp", FsmEvent::Open);
        step_traced(&mut self.fsm, "lcp", FsmEvent::Up)
    }

    /// Handle an inbound LCP packet. Classifies the packet, drives
    /// the FSM, and returns the step plus any extra context needed
    /// for rendering (e.g. for Terminate-Ack the identifier comes
    /// from the inbound packet).
    fn on_packet(&mut self, packet: &LcpPacket<'_>) -> (FsmStep, u8) {
        let id = packet.identifier;
        let event = match packet.typed_code() {
            Some(LcpCode::ConfigureRequest) => {
                self.last_cr_id = id;
                self.last_cr_options = packet.data.to_vec();
                self.classify_configure_request(packet.data)
            }
            Some(LcpCode::ConfigureAck) => FsmEvent::RcvConfigAck,
            Some(LcpCode::ConfigureNak | LcpCode::ConfigureReject) => FsmEvent::RcvConfigNak,
            Some(LcpCode::TerminateRequest) => FsmEvent::RcvTerminateReq,
            Some(LcpCode::TerminateAck) => FsmEvent::RcvTerminateAck,
            Some(LcpCode::CodeReject | LcpCode::ProtocolReject) => FsmEvent::RcvCodeRejPermitted,
            Some(LcpCode::EchoRequest | LcpCode::EchoReply | LcpCode::DiscardRequest) => {
                self.last_rxr_code = packet.code;
                self.last_echo_id = id;
                self.last_echo_data = packet.data.to_vec();
                FsmEvent::RcvEcho
            }
            None => FsmEvent::RcvUnknownCode,
        };
        (step_traced(&mut self.fsm, "lcp", event), id)
    }

    /// Walk an inbound CR option list and decide good/bad. Populates
    /// `pending_nak` with the Reject-able subset (unknown options)
    /// when the verdict is Bad.
    ///
    /// Policy (RFC 1661 §6 + [MS-SSTP] §3.2.5.1):
    /// - MRU, Magic-Number, PFC, ACFC, `AuthProtocol`: accept any
    ///   value.
    /// - Quality-Protocol and any unknown option type: Reject.
    /// - Malformed option lists: treat as RCR- with an empty reject
    ///   body so the peer retransmits.
    fn classify_configure_request(&mut self, opts: &[u8]) -> FsmEvent {
        self.pending_nak.clear();
        self.pending_nak_is_reject = true;
        let mut any_bad = false;
        for parsed in ConfigOptionIter::new(opts) {
            let Ok(opt) = parsed else {
                any_bad = true;
                break;
            };
            if matches!(opt.typed(), Some(LcpOptionId::Mru))
                && let Ok(mru) = opt.as_mru()
            {
                self.peer_mru = Some(mru);
                tracing::trace!(
                    target: "sstp::mtu",
                    peer_mru = mru,
                    "LCP Configure-Request: captured peer MRU for netdev MTU"
                );
            }
            let accept = matches!(
                opt.typed(),
                Some(
                    LcpOptionId::Mru
                        | LcpOptionId::MagicNumber
                        | LcpOptionId::ProtocolFieldCompression
                        | LcpOptionId::AddressControlFieldCompression
                        | LcpOptionId::AuthProtocol
                )
            );
            if !accept {
                any_bad = true;
                // Echo the offending TLV verbatim into the reject body.
                self.pending_nak.push(opt.option_type);
                let total = opt.encoded_len();
                debug_assert!(u8::try_from(total).is_ok());
                #[allow(clippy::cast_possible_truncation)]
                {
                    self.pending_nak.push(total as u8);
                }
                self.pending_nak.extend_from_slice(opt.value);
            }
        }
        if any_bad {
            FsmEvent::RcvConfigReqBad
        } else {
            FsmEvent::RcvConfigReqGood
        }
    }

    /// Render the server's outbound LCP options for its own
    /// Configure-Request: just the negotiated `Auth-Protocol`.
    fn write_own_cr_options(&self, buf: &mut Vec<u8>) {
        match self.auth_method {
            AuthMethod::Pap => {
                let proto = auth_protocol_pap();
                let mut tmp = [0u8; LCP_OPT_HEADER_LEN + 2];
                let n = write_option(&mut tmp, LcpOptionId::AuthProtocol.as_u8(), &proto);
                buf.extend_from_slice(&tmp[..n]);
            }
            AuthMethod::ChapMd5 => {
                let proto = auth_protocol_chap_md5();
                let mut tmp = [0u8; LCP_OPT_HEADER_LEN + 3];
                let n = write_option(&mut tmp, LcpOptionId::AuthProtocol.as_u8(), &proto);
                buf.extend_from_slice(&tmp[..n]);
            }
            AuthMethod::MsChapV2 => {
                let proto = auth_protocol_mschapv2();
                let mut tmp = [0u8; LCP_OPT_HEADER_LEN + 3];
                let n = write_option(&mut tmp, LcpOptionId::AuthProtocol.as_u8(), &proto);
                buf.extend_from_slice(&tmp[..n]);
            }
        }
    }
}

// =============================================================================
//  IPCP server
// =============================================================================

/// Server-side IPCP driver. The server proposes no options of its
/// own; the conversation is driven entirely by Naking the client's
/// 0.0.0.0 `IP-Address` (and `Primary-DNS`/`Primary-NBNS` etc.) into
/// the assigned values.
struct IpcpServer {
    fsm: Fsm,
    addrs: AssignedAddrs,
    /// Server's own end of the tunnel — advertised in our
    /// `Configure-Request` `IP-Address` option so the peer can
    /// install a route via this gateway.
    local_ip: [u8; 4],
    last_cr_id: u8,
    /// For `Send::ConfigureAck` we echo the client's last CR option
    /// list verbatim.
    last_cr_options: Vec<u8>,
    /// For `Send::ConfigureNak` — the Nak/Reject body we built when
    /// classifying the inbound CR as Bad.
    pending_nak: Vec<u8>,
    /// Whether the pending body is a Reject (true) or a Nak (false).
    /// Driver picks the IPCP code accordingly when rendering.
    pending_nak_is_reject: bool,
    opened: bool,
}

impl IpcpServer {
    fn new(addrs: AssignedAddrs, local_ip: [u8; 4]) -> Self {
        Self {
            fsm: Fsm::new(),
            addrs,
            local_ip,
            last_cr_id: 0,
            last_cr_options: Vec::new(),
            pending_nak: Vec::new(),
            pending_nak_is_reject: false,
            opened: false,
        }
    }

    fn open(&mut self) -> FsmStep {
        let _ = step_traced(&mut self.fsm, "ipcp", FsmEvent::Open);
        step_traced(&mut self.fsm, "ipcp", FsmEvent::Up)
    }

    fn on_packet(&mut self, packet: &LcpPacket<'_>) -> (FsmStep, u8) {
        let id = packet.identifier;
        let event = match IpcpCode::from_u8(packet.code) {
            Some(IpcpCode::ConfigureRequest) => {
                self.last_cr_id = id;
                self.last_cr_options = packet.data.to_vec();
                self.classify_configure_request(packet.data)
            }
            Some(IpcpCode::ConfigureAck) => FsmEvent::RcvConfigAck,
            Some(IpcpCode::ConfigureNak | IpcpCode::ConfigureReject) => FsmEvent::RcvConfigNak,
            Some(IpcpCode::TerminateRequest) => FsmEvent::RcvTerminateReq,
            Some(IpcpCode::TerminateAck) => FsmEvent::RcvTerminateAck,
            Some(IpcpCode::CodeReject) => FsmEvent::RcvCodeRejPermitted,
            None => FsmEvent::RcvUnknownCode,
        };
        (step_traced(&mut self.fsm, "ipcp", event), id)
    }

    /// Policy (RFC 1332 §3.3, RFC 1877 §1):
    /// - `IP-Address`: if zero, Nak with our assigned IP; if equal to
    ///   our assigned IP, accept; otherwise Nak with our assigned IP.
    /// - `Primary-DNS` / `Primary-NBNS` / `Secondary-*`: if zero and
    ///   we have an assigned value, Nak with it; if zero and we have
    ///   none, Reject; if non-zero matching ours, accept; if non-zero
    ///   not matching ours, Nak with our value.
    /// - `IP-Compression-Protocol`, `Mobile-IPv4`, unknown: Reject.
    fn classify_configure_request(&mut self, opts: &[u8]) -> FsmEvent {
        self.pending_nak.clear();
        self.pending_nak_is_reject = false;
        let mut nak_body: Vec<u8> = Vec::new();
        let mut reject_body: Vec<u8> = Vec::new();
        for parsed in ConfigOptionIter::new(opts) {
            let Ok(opt) = parsed else {
                return FsmEvent::RcvConfigReqBad;
            };
            let id = IpcpOptionId::from_u8(opt.option_type);
            match id {
                Some(IpcpOptionId::IpAddress) => {
                    if let Ok(v) = read_ipv4_value(opt.value)
                        && v == self.addrs.ip
                    {
                        // Accept as-is.
                        continue;
                    }
                    Self::push_v4_option(
                        &mut nak_body,
                        IpcpOptionId::IpAddress.as_u8(),
                        self.addrs.ip,
                    );
                }
                Some(IpcpOptionId::PrimaryDns) => {
                    Self::handle_optional_dns_like(
                        &mut nak_body,
                        &mut reject_body,
                        &opt,
                        self.addrs.dns1,
                        IpcpOptionId::PrimaryDns.as_u8(),
                    );
                }
                Some(IpcpOptionId::SecondaryDns) => {
                    Self::handle_optional_dns_like(
                        &mut nak_body,
                        &mut reject_body,
                        &opt,
                        self.addrs.dns2,
                        IpcpOptionId::SecondaryDns.as_u8(),
                    );
                }
                Some(IpcpOptionId::PrimaryNbns) => {
                    Self::handle_optional_dns_like(
                        &mut nak_body,
                        &mut reject_body,
                        &opt,
                        self.addrs.nbns1,
                        IpcpOptionId::PrimaryNbns.as_u8(),
                    );
                }
                Some(IpcpOptionId::SecondaryNbns) => {
                    Self::handle_optional_dns_like(
                        &mut nak_body,
                        &mut reject_body,
                        &opt,
                        self.addrs.nbns2,
                        IpcpOptionId::SecondaryNbns.as_u8(),
                    );
                }
                Some(IpcpOptionId::IpCompressionProtocol | IpcpOptionId::MobileIpv4) | None => {
                    // Reject the offending TLV verbatim.
                    reject_body.push(opt.option_type);
                    let total = opt.encoded_len();
                    debug_assert!(u8::try_from(total).is_ok());
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        reject_body.push(total as u8);
                    }
                    reject_body.extend_from_slice(opt.value);
                }
            }
        }
        // RFC 1661 §6: Reject takes precedence over Nak. If we have a
        // Reject body, the FSM sends that first; the client will
        // retransmit a fresh CR without the rejected options, and we
        // then Nak the value-mismatch options on the next round.
        if !reject_body.is_empty() {
            self.pending_nak = reject_body;
            self.pending_nak_is_reject = true;
            FsmEvent::RcvConfigReqBad
        } else if !nak_body.is_empty() {
            self.pending_nak = nak_body;
            self.pending_nak_is_reject = false;
            FsmEvent::RcvConfigReqBad
        } else {
            FsmEvent::RcvConfigReqGood
        }
    }

    fn handle_optional_dns_like(
        nak: &mut Vec<u8>,
        reject: &mut Vec<u8>,
        opt: &ConfigOption<'_>,
        ours: Option<[u8; 4]>,
        opt_type: u8,
    ) {
        match (ours, read_ipv4_value(opt.value)) {
            (Some(v), Ok(client)) if client == v => {
                // Accept.
            }
            (Some(v), Ok(_) | Err(_)) => Self::push_v4_option(nak, opt_type, v),
            (None, _) => {
                // Reject — we have no value to advertise.
                reject.push(opt_type);
                let total = opt.encoded_len();
                debug_assert!(u8::try_from(total).is_ok());
                #[allow(clippy::cast_possible_truncation)]
                {
                    reject.push(total as u8);
                }
                reject.extend_from_slice(opt.value);
            }
        }
    }

    fn push_v4_option(buf: &mut Vec<u8>, opt_type: u8, addr: [u8; 4]) {
        push_v4_option(buf, opt_type, addr);
    }
}

fn push_v4_option(buf: &mut Vec<u8>, opt_type: u8, addr: [u8; 4]) {
    let mut tmp = [0u8; IPV4_OPTION_TOTAL_LEN];
    let n = write_ipv4_option(&mut tmp, opt_type, addr);
    buf.extend_from_slice(&tmp[..n]);
}

// =============================================================================
//  Top-level orchestrator
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// LCP negotiating; auth has not started.
    Establish,
    /// LCP Opened. For PAP, waiting for the peer's
    /// `Authenticate-Request`. For CHAP, the server's `Challenge`
    /// has been sent and we're waiting for the peer's `Response`.
    AuthPending,
    /// PAP credentials handed to the session task via `NeedPapAuth`,
    /// or CHAP response handed via `NeedChapAuth`; waiting for
    /// [`Ppp::on_auth_result`].
    AuthInFlight { method: InFlightMethod },
    /// Auth accepted; IPCP negotiating.
    Network,
    /// LCP terminating or terminated.
    Dead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InFlightMethod {
    Pap { pap_id: u8 },
    Chap { chap_id: u8 },
    MsChapV2 { chap_id: u8 },
}

/// PPP driver orchestrator. Owns LCP + IPCP sub-drivers and the
/// in-flight authentication state.
pub struct Ppp {
    phase: Phase,
    lcp: LcpServer,
    ipcp: Option<IpcpServer>,
    /// Addresses to feed IPCP once auth completes. `None` until
    /// `on_auth_result(Accept)` runs.
    pending_addrs: Option<AssignedAddrs>,
    /// Server's own IPv4 address advertised in the IPCP
    /// `Configure-Request` so the peer learns its tunnel gateway
    /// ([RFC 1332] §3.3). Without this the client invents an
    /// arbitrary peer address (MikroTik defaults to a 10.112/16
    /// pool) and on-link routing fails.
    local_ip: [u8; 4],
    /// CHAP challenge most recently sent to the peer ([RFC 1994]
    /// §4.1) — populated when entering `AuthPending` under CHAP
    /// and forwarded as `CHAP-Challenge` to RADIUS once the peer's
    /// `Response` arrives. `None` until the challenge is generated
    /// (always `None` under PAP).
    chap_challenge: Option<[u8; 16]>,
    /// Identifier counter for outbound CHAP packets.
    chap_id_counter: u8,
    /// Identifier counter for outbound LCP packets the driver
    /// generates outside the FSM (Protocol-Reject — [RFC 1661]
    /// §5.7 requires a fresh Identifier per packet).
    lcp_extra_id_counter: u8,
}

impl Ppp {
    /// Build the driver. The caller must invoke [`Ppp::open`] to
    /// kick off the LCP exchange.
    #[must_use]
    pub fn new(local_ip: [u8; 4], auth_method: AuthMethod) -> Self {
        Self {
            phase: Phase::Establish,
            lcp: LcpServer::new(auth_method),
            ipcp: None,
            pending_addrs: None,
            local_ip,
            chap_challenge: None,
            chap_id_counter: 0,
            lcp_extra_id_counter: 0,
        }
    }

    /// Send the server's initial LCP `Configure-Request`. Returns the
    /// step containing the encoded frame and the LCP restart timer.
    pub fn open(&mut self) -> PppStep {
        let step = self.lcp.open();
        self.render_lcp_step(step)
    }

    /// Drive an inbound PPP frame (already demultiplexed from its
    /// SSTP data packet — i.e. the raw PPP frame bytes including the
    /// optional Address/Control + Protocol prefix).
    pub fn on_frame(&mut self, payload: &[u8]) -> PppStep {
        let Ok(frame) = decode_frame(payload) else {
            // Malformed PPP frame: drop. The peer will retransmit
            // or LCP will eventually terminate via Max-Failure.
            return PppStep::default();
        };
        match (self.phase, ProtocolId::from_u16(frame.protocol)) {
            // LCP is accepted in any phase ([RFC 1661] §3.2–3.6).
            (_, Some(ProtocolId::Lcp)) => self.handle_lcp(frame.info),

            // Auth protocols: accepted in AuthPending (first attempt)
            // and AuthInFlight (retransmit while awaiting RADIUS).
            // Silently discarded in Network (auth already done — a
            // late retransmit) per RFC 1661 §5.7 note: Protocol-Reject
            // signals "unsupported" which is incorrect for a protocol
            // we completed. In Establish we discard (LCP not open yet).
            (Phase::AuthPending | Phase::AuthInFlight { .. }, Some(ProtocolId::Pap)) => {
                self.handle_pap(frame.info)
            }
            (Phase::AuthPending | Phase::AuthInFlight { .. }, Some(ProtocolId::Chap)) => {
                self.handle_chap(frame.info)
            }
            (_, Some(ProtocolId::Pap | ProtocolId::Chap)) => {
                // Late auth retransmit after Network, or before LCP
                // opens — silently discard ([RFC 1661] §3.3 / §3.4).
                PppStep::default()
            }

            // IPCP: accepted in Network phase. During auth phases,
            // silently discard per [RFC 1661] §3.3: "All other packets
            // received during this phase MUST be silently discarded."
            (Phase::Network, Some(ProtocolId::Ipcp)) => self.handle_ipcp(frame.info),
            (_, Some(ProtocolId::Ipcp)) => PppStep::default(),

            // Anything else: send an LCP Protocol-Reject if LCP is
            // in the Opened state ([RFC 1661] §5.7). The common
            // case is a Windows client probing CCP (0x80FD) for
            // MPPE/MPPC even though SSTP forbids PPP-level
            // encryption — without a polite reject the client
            // retransmits its CCP `Configure-Request` until LCP
            // Max-Failure tears the link down. ECP (0x8053),
            // Multilink (0x003D), CBCP (0xC029) and any future
            // unrecognised protocol are handled the same way.
            // Before LCP opens, [RFC 1661] §5.7 requires us to
            // silently discard rather than reject.
            _ => self.protocol_reject(frame.protocol, frame.info),
        }
    }

    /// Build an LCP `Protocol-Reject` ([RFC 1661] §5.7) for an
    /// inbound frame whose protocol we don't speak. Returns an empty
    /// step if LCP is not in Opened state.
    fn protocol_reject(&mut self, rejected_protocol: u16, rejected_info: &[u8]) -> PppStep {
        if !self.lcp.opened {
            return PppStep::default();
        }
        // Body = Rejected-Protocol (2B) + Rejected-Information.
        // Truncate so the entire LCP packet fits in our default
        // MRU; we don't track the peer's MRU explicitly but every
        // implementation in the wild offers ≥ 1500.
        let max_body = (DEFAULT_MRU as usize)
            .saturating_sub(LCP_HEADER_LEN)
            .saturating_sub(2);
        let info_len = rejected_info.len().min(max_body);
        let mut body = Vec::with_capacity(2 + info_len);
        body.extend_from_slice(&rejected_protocol.to_be_bytes());
        body.extend_from_slice(&rejected_info[..info_len]);
        let id = self.lcp_extra_id_counter;
        self.lcp_extra_id_counter = self.lcp_extra_id_counter.wrapping_add(1);
        tracing::debug!(
            target: "sstp::ppp",
            protocol = format_args!("0x{rejected_protocol:04x}"),
            info_bytes = info_len,
            id = id,
            "PPP Protocol-Reject"
        );
        let mut step = PppStep::default();
        step.push_frame(encode_lcp_frame(LcpCode::ProtocolReject, id, &body));
        step
    }

    /// LCP / IPCP restart timer expired. Returns the resulting step.
    pub fn on_timer(&mut self, owner: TimerOwner) -> PppStep {
        match owner {
            TimerOwner::Lcp => {
                let step = step_traced(&mut self.lcp.fsm, "lcp", FsmEvent::RestartTimeout);
                self.render_lcp_step(step)
            }
            TimerOwner::Ipcp => match self.ipcp.as_mut() {
                Some(ipcp) => {
                    let step = step_traced(&mut ipcp.fsm, "ipcp", FsmEvent::RestartTimeout);
                    self.render_ipcp_step(step)
                }
                None => PppStep::default(),
            },
        }
    }

    /// Apply a RADIUS verdict to the in-flight authentication
    /// exchange (PAP or CHAP-MD5). MS-CHAPv2 verdicts must use
    /// [`Ppp::on_mschap_result`] because they carry the
    /// Authenticator-Response body that goes inside the CHAP
    /// Success packet.
    pub fn on_auth_result(&mut self, verdict: AuthVerdict) -> PppStep {
        let Phase::AuthInFlight { method } = self.phase else {
            return PppStep::default();
        };
        let mut step = PppStep::default();
        match (method, verdict) {
            (InFlightMethod::Pap { pap_id }, AuthVerdict::Accept { addrs }) => {
                let mut body = [0u8; 16];
                let n = pap::encode_response(&mut body, pap::Code::AuthenticateAck, pap_id, &[]);
                step.push_frame(encode_pap_frame(&body[..n]));
                self.advance_to_network(&mut step, addrs);
            }
            (InFlightMethod::Pap { pap_id }, AuthVerdict::Reject { message }) => {
                let mut body = [0u8; 16];
                let n = pap::encode_response(
                    &mut body,
                    pap::Code::AuthenticateNak,
                    pap_id,
                    message.get(..message.len().min(11)).unwrap_or(&[]),
                );
                step.push_frame(encode_pap_frame(&body[..n]));
                self.tear_down_after_reject(&mut step);
            }
            (InFlightMethod::Chap { chap_id }, AuthVerdict::Accept { addrs }) => {
                step.push_frame(encode_chap_terminal(chap::Code::Success, chap_id, b""));
                self.advance_to_network(&mut step, addrs);
            }
            (InFlightMethod::Chap { chap_id }, AuthVerdict::Reject { message }) => {
                // CHAP Failure carries an opaque message (free-form
                // text per [RFC 1994] §4.3); cap to keep the frame
                // small.
                let trimmed = message.get(..message.len().min(255)).unwrap_or(&[]);
                step.push_frame(encode_chap_terminal(chap::Code::Failure, chap_id, trimmed));
                self.tear_down_after_reject(&mut step);
            }
            (InFlightMethod::MsChapV2 { .. }, _) => {
                // MS-CHAPv2 must use on_mschap_result. Caller bug —
                // drop and let the LCP restart timer reap.
            }
        }
        step
    }

    /// Apply a RADIUS verdict to an in-flight MS-CHAPv2 exchange.
    ///
    /// On Accept the driver emits a PPP CHAP `Success` packet whose
    /// body is the `S=<40-hex>` Authenticator-Response from the
    /// `MS-CHAP2-Success` VSA ([RFC 2759] §6 / RFC 2548 §2.3.3).
    /// `auth_response` is the VSA body with its leading CHAP-Identifier
    /// byte already stripped (see [`crate::auth::reply::decode_accept`]).
    /// If the authenticator omitted the VSA, the Success body is
    /// empty — the peer typically tears down with an "Authenticator
    /// Response invalid" error in that case.
    ///
    /// On Reject the driver emits a CHAP `Failure` whose body is
    /// the supplied `error_string` if any (typically lifted from the
    /// `MS-CHAP-Error` VSA, RFC 2548 §2.1.2), otherwise a synthesised
    /// `E=691 R=0 V=3 M=...` payload built from the reject message.
    pub fn on_mschap_result(
        &mut self,
        verdict: AuthVerdict,
        auth_response: Option<&[u8]>,
        error_string: Option<&str>,
    ) -> PppStep {
        let Phase::AuthInFlight {
            method: InFlightMethod::MsChapV2 { chap_id },
        } = self.phase
        else {
            return PppStep::default();
        };
        let mut step = PppStep::default();
        match verdict {
            AuthVerdict::Accept { addrs } => {
                let body = auth_response.unwrap_or(&[]);
                let trimmed = body.get(..body.len().min(255)).unwrap_or(&[]);
                step.push_frame(encode_chap_terminal(chap::Code::Success, chap_id, trimmed));
                self.advance_to_network(&mut step, addrs);
            }
            AuthVerdict::Reject { message } => {
                let synth;
                let body: &[u8] = if let Some(s) = error_string {
                    s.as_bytes()
                } else {
                    let msg = String::from_utf8_lossy(&message);
                    synth = format!("E=691 R=0 V=3 M={msg}");
                    synth.as_bytes()
                };
                let trimmed = body.get(..body.len().min(255)).unwrap_or(&[]);
                step.push_frame(encode_chap_terminal(chap::Code::Failure, chap_id, trimmed));
                self.tear_down_after_reject(&mut step);
            }
        }
        step
    }

    fn advance_to_network(&mut self, step: &mut PppStep, addrs: AssignedAddrs) {
        // Fold the peer's advertised MRU into the netdev MTU. The
        // link MTU is the minimum of (a) what the peer can receive
        // (LCP MRU, [RFC 1661] §6.1) and (b) what RADIUS policy
        // dictates (`Framed-MTU`, RFC 2865 §5.12). RADIUS wins on
        // ties — it represents operator policy — but if RADIUS
        // omits Framed-MTU we fall back to the peer's MRU.
        let mut addrs = addrs;
        addrs.mtu = match (addrs.mtu, self.lcp.peer_mru) {
            (Some(framed), Some(peer)) => {
                let merged = framed.min(peer);
                if merged != framed {
                    tracing::debug!(
                        target: "sstp::mtu",
                        framed_mtu = framed,
                        peer_mru = peer,
                        merged,
                        "netdev MTU clamped by peer MRU"
                    );
                }
                Some(merged)
            }
            (Some(framed), None) => Some(framed),
            (None, Some(peer)) => {
                tracing::debug!(
                    target: "sstp::mtu",
                    peer_mru = peer,
                    "netdev MTU sourced from peer MRU (no Framed-MTU from RADIUS)"
                );
                Some(peer)
            }
            (None, None) => None,
        };
        self.pending_addrs = Some(addrs);
        self.phase = Phase::Network;
        let mut ipcp = IpcpServer::new(addrs, self.local_ip);
        let fsm_step = ipcp.open();
        self.ipcp = Some(ipcp);
        let ipcp_step = self.render_ipcp_step(fsm_step);
        step.frames.extend(ipcp_step.frames);
        step.timer_starts.extend(ipcp_step.timer_starts);
        step.timer_stops.extend(ipcp_step.timer_stops);
        if ipcp_step.event.is_some() {
            step.event = ipcp_step.event;
        }
        step.finished |= ipcp_step.finished;
    }

    fn tear_down_after_reject(&mut self, step: &mut PppStep) {
        let close = step_traced(&mut self.lcp.fsm, "lcp", FsmEvent::Close);
        let close_step = self.render_lcp_step(close);
        step.frames.extend(close_step.frames);
        step.timer_starts.extend(close_step.timer_starts);
        step.timer_stops.extend(close_step.timer_stops);
        step.finished = true;
        self.phase = Phase::Dead;
    }

    fn next_chap_id(&mut self) -> u8 {
        let id = self.chap_id_counter;
        self.chap_id_counter = self.chap_id_counter.wrapping_add(1);
        id
    }

    fn handle_lcp(&mut self, info: &[u8]) -> PppStep {
        let Ok(packet) = decode_lcp_packet(info) else {
            return PppStep::default();
        };
        let (step, _id) = self.lcp.on_packet(&packet);
        self.render_lcp_step(step)
    }

    fn handle_pap(&mut self, info: &[u8]) -> PppStep {
        // We expect Authenticate-Request only; ignore anything else.
        let Ok(req) = pap::decode_authenticate_request(info) else {
            return PppStep::default();
        };
        self.phase = Phase::AuthInFlight {
            method: InFlightMethod::Pap {
                pap_id: req.identifier,
            },
        };
        PppStep {
            event: Some(PppEvent::NeedPapAuth {
                peer_id: req.peer_id.to_vec(),
                password: req.password.to_vec(),
            }),
            ..PppStep::default()
        }
    }

    fn handle_chap(&mut self, info: &[u8]) -> PppStep {
        // We expect a CHAP `Response` here. Anything else (a stray
        // Challenge from the peer, Success/Failure, malformed) is
        // dropped.
        let Ok(resp) = chap::decode_challenge_response(info) else {
            return PppStep::default();
        };
        match self.lcp.auth_method {
            AuthMethod::ChapMd5 => {
                // CHAP-MD5 response value is exactly 16 bytes
                // ([RFC 1994] §4.1).
                if resp.value.len() != 16 {
                    return PppStep::default();
                }
                let mut response = [0u8; 16];
                response.copy_from_slice(resp.value);
                let username = resp.name.to_vec();
                let Some(challenge) = self.chap_challenge else {
                    // Peer responded before we sent a challenge.
                    return PppStep::default();
                };
                self.phase = Phase::AuthInFlight {
                    method: InFlightMethod::Chap {
                        chap_id: resp.identifier,
                    },
                };
                PppStep {
                    event: Some(PppEvent::NeedChapAuth {
                        username,
                        chap_id: resp.identifier,
                        challenge,
                        response,
                    }),
                    ..PppStep::default()
                }
            }
            AuthMethod::MsChapV2 => {
                // MS-CHAPv2 Response value is exactly 49 bytes
                // ([RFC 2759] §6):
                // Peer-Challenge[16] | Reserved[8] | NT-Response[24]
                // | Flags[1].
                if resp.value.len() != 49 {
                    return PppStep::default();
                }
                if resp.value[16..24].iter().any(|&b| b != 0) {
                    // Reserved field must be all zeros.
                    return PppStep::default();
                }
                let mut peer_challenge = [0u8; 16];
                peer_challenge.copy_from_slice(&resp.value[0..16]);
                let mut nt_response = [0u8; 24];
                nt_response.copy_from_slice(&resp.value[24..48]);
                let flags = resp.value[48];
                let mut authenticator_challenge = [0u8; 16];
                let Some(challenge) = self.chap_challenge else {
                    // Should not happen — we generate a 16-byte
                    // challenge before sending it.
                    return PppStep::default();
                };
                authenticator_challenge.copy_from_slice(&challenge);
                let username = resp.name.to_vec();
                self.phase = Phase::AuthInFlight {
                    method: InFlightMethod::MsChapV2 {
                        chap_id: resp.identifier,
                    },
                };
                PppStep {
                    event: Some(PppEvent::NeedMsChapV2Auth {
                        username,
                        chap_id: resp.identifier,
                        authenticator_challenge,
                        peer_challenge,
                        nt_response,
                        flags,
                    }),
                    ..PppStep::default()
                }
            }
            AuthMethod::Pap => {
                // CHAP frame received during a PAP-only negotiation
                // — ignore.
                PppStep::default()
            }
        }
    }

    fn handle_ipcp(&mut self, info: &[u8]) -> PppStep {
        let Ok(packet) = decode_lcp_packet(info) else {
            return PppStep::default();
        };
        let Some(ipcp) = self.ipcp.as_mut() else {
            return PppStep::default();
        };
        let (step, _id) = ipcp.on_packet(&packet);
        self.render_ipcp_step(step)
    }

    fn render_lcp_step(&mut self, step: FsmStep) -> PppStep {
        let mut out = PppStep::default();
        render_send(&mut out, &mut self.lcp, step.send, TimerOwner::Lcp, true);
        render_send(
            &mut out,
            &mut self.lcp,
            step.send_extra,
            TimerOwner::Lcp,
            false,
        );
        apply_timer(&mut out, step.restart_timer, TimerOwner::Lcp);
        if step.notify.up && !self.lcp.opened {
            self.lcp.opened = true;
            // LCP Opened → enter auth phase.
            self.phase = Phase::AuthPending;
            // Under CHAP-MD5 the server is the authenticator; emit
            // a Challenge ([RFC 1994] §4.1) immediately so the peer
            // can compute its response. Under PAP the peer drives
            // the exchange and we wait for its `Authenticate-Request`.
            if self.lcp.auth_method == AuthMethod::ChapMd5
                || self.lcp.auth_method == AuthMethod::MsChapV2
            {
                let challenge = generate_chap_challenge();
                let chap_id = self.next_chap_id();
                let frame = encode_chap_challenge(chap_id, &challenge);
                self.chap_challenge = Some(challenge);
                out.push_frame(frame);
            }
        }
        if step.notify.down {
            self.lcp.opened = false;
        }
        if step.notify.finished {
            out.finished = true;
            self.phase = Phase::Dead;
        }
        out
    }

    fn render_ipcp_step(&mut self, step: FsmStep) -> PppStep {
        let mut out = PppStep::default();
        let ipcp = self.ipcp.as_mut().expect("ipcp must exist when rendering");
        render_ipcp_send(&mut out, ipcp, step.send, true);
        render_ipcp_send(&mut out, ipcp, step.send_extra, false);
        apply_timer(&mut out, step.restart_timer, TimerOwner::Ipcp);
        if step.notify.up && !ipcp.opened {
            ipcp.opened = true;
            if let Some(addrs) = self.pending_addrs {
                out.event = Some(PppEvent::NetworkUp(addrs));
            }
        }
        if step.notify.finished {
            out.finished = true;
        }
        out
    }
}

impl Default for Ppp {
    fn default() -> Self {
        Self::new([0, 0, 0, 0], AuthMethod::Pap)
    }
}

// =============================================================================
//  Rendering helpers
// =============================================================================

fn apply_timer(out: &mut PppStep, op: Option<RestartTimer>, owner: TimerOwner) {
    match op {
        Some(RestartTimer::Start) => out.timer_starts.push((owner, DEFAULT_RESTART)),
        Some(RestartTimer::Stop) => out.timer_stops.push(owner),
        None => {}
    }
}

fn render_send(
    out: &mut PppStep,
    lcp: &mut LcpServer,
    send: Option<FsmSend>,
    owner: TimerOwner,
    _is_primary: bool,
) {
    let _ = owner;
    let Some(send) = send else { return };
    let mut body: Vec<u8> = Vec::with_capacity(32);
    let (code, identifier) = match send {
        FsmSend::ConfigureRequest => {
            let id = lcp.fsm.bump_identifier();
            lcp.write_own_cr_options(&mut body);
            (LcpCode::ConfigureRequest, id)
        }
        FsmSend::ConfigureAck => {
            body.extend_from_slice(&lcp.last_cr_options);
            (LcpCode::ConfigureAck, lcp.last_cr_id)
        }
        FsmSend::ConfigureNak => {
            body.extend_from_slice(&lcp.pending_nak);
            let code = if lcp.pending_nak_is_reject {
                LcpCode::ConfigureReject
            } else {
                LcpCode::ConfigureNak
            };
            (code, lcp.last_cr_id)
        }
        FsmSend::TerminateReq => {
            let id = lcp.fsm.bump_identifier();
            (LcpCode::TerminateRequest, id)
        }
        FsmSend::TerminateAck => (LcpCode::TerminateAck, lcp.last_cr_id),
        FsmSend::EchoReply => {
            // Only respond to Echo-Request ([RFC 1661] §5.8); the
            // FSM emits `EchoReply` for any RXR-class packet, but
            // Echo-Reply and Discard-Request must not generate a
            // reply. Required to keep long-running sessions alive
            // — pppd-style peers (Windows, sstpc) send an
            // Echo-Request every `lcp-echo-interval` seconds and
            // disconnect after `lcp-echo-failure` missed replies.
            if lcp.last_rxr_code != LcpCode::EchoRequest.as_u8() {
                return;
            }
            // Body = Magic-Number (4B, zero — we don't negotiate
            // the option, [RFC 1661] §6.4 permits zero) + the
            // request's data field copied through.
            body.extend_from_slice(&[0, 0, 0, 0]);
            if lcp.last_echo_data.len() > 4 {
                body.extend_from_slice(&lcp.last_echo_data[4..]);
            }
            (LcpCode::EchoReply, lcp.last_echo_id)
        }
        FsmSend::CodeReject => {
            // v0.1: Code-Reject is emitted by the FSM only for
            // unrecognised LCP codes. We don't have the inbound
            // packet body cached for that path; log-and-drop is
            // acceptable because the peer will resync via its
            // own retransmit timer.
            return;
        }
    };
    out.push_frame(encode_lcp_frame(code, identifier, &body));
}

fn render_ipcp_send(
    out: &mut PppStep,
    ipcp: &mut IpcpServer,
    send: Option<FsmSend>,
    _is_primary: bool,
) {
    let Some(send) = send else { return };
    let mut body: Vec<u8> = Vec::with_capacity(32);
    let (code, identifier) = match send {
        FsmSend::ConfigureRequest => {
            let id = ipcp.fsm.bump_identifier();
            // Advertise the server's tunnel address so the peer can
            // install a route via this gateway ([RFC 1332] §3.3).
            // Without this option the peer either invents a fallback
            // (MikroTik picks from its default pool) or never
            // installs a usable next-hop, and ping across the
            // tunnel times out.
            push_v4_option(&mut body, IpcpOptionId::IpAddress.as_u8(), ipcp.local_ip);
            (IpcpCode::ConfigureRequest, id)
        }
        FsmSend::ConfigureAck => {
            body.extend_from_slice(&ipcp.last_cr_options);
            (IpcpCode::ConfigureAck, ipcp.last_cr_id)
        }
        FsmSend::ConfigureNak => {
            body.extend_from_slice(&ipcp.pending_nak);
            let code = if ipcp.pending_nak_is_reject {
                IpcpCode::ConfigureReject
            } else {
                IpcpCode::ConfigureNak
            };
            (code, ipcp.last_cr_id)
        }
        FsmSend::TerminateReq => {
            let id = ipcp.fsm.bump_identifier();
            (IpcpCode::TerminateRequest, id)
        }
        FsmSend::TerminateAck => (IpcpCode::TerminateAck, ipcp.last_cr_id),
        FsmSend::CodeReject | FsmSend::EchoReply => return,
    };
    out.push_frame(encode_ipcp_frame(code, identifier, &body));
}

fn encode_lcp_frame(code: LcpCode, identifier: u8, body: &[u8]) -> Vec<u8> {
    encode_protocol_packet(ProtocolId::Lcp.as_u16(), code.as_u8(), identifier, body)
}

fn encode_ipcp_frame(code: IpcpCode, identifier: u8, body: &[u8]) -> Vec<u8> {
    encode_protocol_packet(ProtocolId::Ipcp.as_u16(), code.as_u8(), identifier, body)
}

fn encode_pap_frame(packet: &[u8]) -> Vec<u8> {
    // PAP packet is already fully encoded (header + body). Wrap it
    // in a PPP frame with the PAP protocol id.
    let mut out = vec![0u8; 4 + packet.len()];
    let n = encode_frame(&mut out, ProtocolId::Pap.as_u16(), packet);
    out.truncate(n);
    out
}

fn encode_chap_frame(packet: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 4 + packet.len()];
    let n = encode_frame(&mut out, ProtocolId::Chap.as_u16(), packet);
    out.truncate(n);
    out
}

/// Encode a CHAP `Challenge` PPP frame ready for SSTP wrapping.
/// Server name in the Name field is informational ([RFC 1994]
/// §4.1) — clients commonly ignore it.
fn encode_chap_challenge(identifier: u8, challenge: &[u8]) -> Vec<u8> {
    const NAME: &[u8] = b"sstp-server";
    let total = chap::HEADER_LEN + 1 + challenge.len() + NAME.len();
    let mut packet = vec![0u8; total];
    let n = chap::encode_challenge_response(
        &mut packet,
        chap::Code::Challenge,
        identifier,
        challenge,
        NAME,
    );
    packet.truncate(n);
    encode_chap_frame(&packet)
}

/// Encode a CHAP `Success` or `Failure` PPP frame.
fn encode_chap_terminal(code: chap::Code, identifier: u8, message: &[u8]) -> Vec<u8> {
    let total = chap::HEADER_LEN + message.len();
    let mut packet = vec![0u8; total];
    let n = chap::encode_terminal(&mut packet, code, identifier, message);
    packet.truncate(n);
    encode_chap_frame(&packet)
}

/// Generate a fresh 16-byte CHAP challenge ([RFC 1994] §4.1
/// recommends ≥8 octets; 16 matches MD5 block size and is what
/// FreeRADIUS / strongSwan emit).
fn generate_chap_challenge() -> [u8; 16] {
    use std::mem::MaybeUninit;
    let mut buf = [MaybeUninit::<u8>::uninit(); 16];
    crate::crypto::rand::fill_bytes(&mut buf);
    // SAFETY: fill_bytes fully initialises every element.
    unsafe { buf.map(|x| x.assume_init()) }
}

/// Build a PPP frame containing an LCP-format packet (Code +
/// Identifier + Length + body) for the given protocol id.
fn encode_protocol_packet(protocol: u16, code: u8, identifier: u8, body: &[u8]) -> Vec<u8> {
    let total = LCP_HEADER_LEN + body.len();
    debug_assert!(
        u16::try_from(total).is_ok(),
        "PPP protocol packet too large"
    );
    let mut header = [0u8; LCP_HEADER_LEN];
    #[allow(clippy::cast_possible_truncation)]
    write_lcp_header(&mut header, code, identifier, total as u16);
    // Compose: Addr(1)+Ctl(1)+Protocol(2)+Header(4)+Body
    let mut out = vec![0u8; 4 + total];
    out[0] = ADDRESS_ALL_STATIONS;
    out[1] = CONTROL_UI;
    out[2..4].copy_from_slice(&protocol.to_be_bytes());
    out[4..4 + LCP_HEADER_LEN].copy_from_slice(&header);
    out[4 + LCP_HEADER_LEN..].copy_from_slice(body);
    out
}

// =============================================================================
//  Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode the protocol id + LCP-format header off an encoded
    /// PPP frame produced by the driver.
    fn peel(frame: &[u8]) -> (u16, u8, u8, &[u8]) {
        assert_eq!(frame[0], ADDRESS_ALL_STATIONS);
        assert_eq!(frame[1], CONTROL_UI);
        let proto = u16::from_be_bytes([frame[2], frame[3]]);
        let code = frame[4];
        let id = frame[5];
        let len = u16::from_be_bytes([frame[6], frame[7]]) as usize;
        assert_eq!(len, frame.len() - 4);
        (proto, code, id, &frame[8..4 + len])
    }

    fn lcp_cr(id: u8, opts: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(opts);
        encode_lcp_frame(LcpCode::ConfigureRequest, id, &body)
    }

    fn ipcp_cr(id: u8, opts: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(opts);
        encode_ipcp_frame(IpcpCode::ConfigureRequest, id, &body)
    }

    #[test]
    fn open_emits_lcp_configure_request_with_pap() {
        let mut ppp = Ppp::new([0, 0, 0, 0], AuthMethod::Pap);
        let step = ppp.open();
        assert_eq!(step.frames.len(), 1);
        let (proto, code, _id, opts) = peel(&step.frames[0]);
        assert_eq!(proto, ProtocolId::Lcp.as_u16());
        assert_eq!(code, LcpCode::ConfigureRequest.as_u8());
        // First option is Auth-Protocol = PAP (type 3, len 4).
        assert_eq!(opts[0], LcpOptionId::AuthProtocol.as_u8());
        assert_eq!(opts[1], 4);
        assert_eq!(&opts[2..4], &ProtocolId::Pap.as_u16().to_be_bytes());
        // Restart timer armed for LCP.
        assert_eq!(step.timer_starts, vec![(TimerOwner::Lcp, DEFAULT_RESTART)]);
    }

    #[test]
    fn ack_acceptable_lcp_cr() {
        let mut ppp = Ppp::new([0, 0, 0, 0], AuthMethod::Pap);
        let _open = ppp.open();
        // Client CR: MRU=1500, Magic, PFC, ACFC.
        let opts: Vec<u8> = vec![
            0x01, 0x04, 0x05, 0xdc, // MRU=1500
            0x05, 0x06, 0xde, 0xad, 0xbe, 0xef, // Magic
            0x07, 0x02, // PFC
            0x08, 0x02, // ACFC
        ];
        let frame = lcp_cr(7, &opts);
        let step = ppp.on_frame(&frame);
        assert_eq!(step.frames.len(), 1);
        let (proto, code, id, body) = peel(&step.frames[0]);
        assert_eq!(proto, ProtocolId::Lcp.as_u16());
        assert_eq!(code, LcpCode::ConfigureAck.as_u8());
        assert_eq!(id, 7);
        assert_eq!(body, opts.as_slice());
    }

    #[test]
    fn rejects_unknown_lcp_option() {
        let mut ppp = Ppp::new([0, 0, 0, 0], AuthMethod::Pap);
        let _open = ppp.open();
        // Option type 99 (unknown) plus a known MRU.
        let opts: Vec<u8> = vec![
            0x63, 0x03, 0xaa, // unknown type 99
            0x01, 0x04, 0x05, 0xdc, // MRU=1500
        ];
        let frame = lcp_cr(3, &opts);
        let step = ppp.on_frame(&frame);
        assert_eq!(step.frames.len(), 1);
        let (_, code, id, body) = peel(&step.frames[0]);
        assert_eq!(code, LcpCode::ConfigureReject.as_u8());
        assert_eq!(id, 3);
        // Only the rejected option is echoed.
        assert_eq!(body, &[0x63, 0x03, 0xaa]);
    }

    #[test]
    fn lcp_opened_transitions_to_auth_pending() {
        let mut ppp = Ppp::new([0, 0, 0, 0], AuthMethod::Pap);
        let _ = ppp.open();
        // Client sends an Ack to our CR (using id=1, the bumped id).
        let ack = encode_lcp_frame(
            LcpCode::ConfigureAck,
            1,
            &[
                0x03, 0x04, 0xc0, 0x23, // Auth-Protocol = PAP
            ],
        );
        let _step = ppp.on_frame(&ack);
        assert!(matches!(ppp.phase, Phase::Establish));
        // Client sends its own CR — empty (accept defaults).
        let cr = lcp_cr(9, &[]);
        let step = ppp.on_frame(&cr);
        // Should emit Configure-Ack and transition to AuthPending.
        assert_eq!(step.frames.len(), 1);
        let (_, code, _, _) = peel(&step.frames[0]);
        assert_eq!(code, LcpCode::ConfigureAck.as_u8());
        assert!(matches!(ppp.phase, Phase::AuthPending));
    }

    fn drive_to_auth_pending(ppp: &mut Ppp) {
        let _ = ppp.open();
        // Ack our CR.
        let ack = encode_lcp_frame(LcpCode::ConfigureAck, 1, &[0x03, 0x04, 0xc0, 0x23]);
        let _ = ppp.on_frame(&ack);
        // Peer CR (empty) — we Ack it, LCP Opened.
        let cr = lcp_cr(5, &[]);
        let _ = ppp.on_frame(&cr);
        assert!(matches!(ppp.phase, Phase::AuthPending));
    }

    #[test]
    fn unknown_protocol_before_lcp_opens_is_silently_dropped() {
        let mut ppp = Ppp::new([0, 0, 0, 0], AuthMethod::Pap);
        let _ = ppp.open();
        // CCP (0x80FD) Configure-Request before LCP has opened —
        // [RFC 1661] §5.7 forbids Protocol-Reject outside Opened
        // state. We must drop silently.
        let mut frame = vec![ADDRESS_ALL_STATIONS, CONTROL_UI, 0x80, 0xfd];
        frame.extend_from_slice(&[0x01, 0x2a, 0x00, 0x04]);
        let step = ppp.on_frame(&frame);
        assert!(step.frames.is_empty());
    }

    #[test]
    fn ccp_configure_request_after_lcp_open_gets_protocol_reject() {
        let mut ppp = Ppp::new([0, 0, 0, 0], AuthMethod::Pap);
        drive_to_auth_pending(&mut ppp);
        // CCP Configure-Request proposing MPPC/MPPE — Windows
        // clients send this even when SSTP forbids PPP-level
        // encryption. We must Protocol-Reject so the client stops
        // retrying ([RFC 1661] §5.7).
        let ccp_body = [0x01, 0x07, 0x00, 0x0a, 0x12, 0x06, 0x01, 0x00, 0x00, 0x40];
        let mut frame = vec![ADDRESS_ALL_STATIONS, CONTROL_UI, 0x80, 0xfd];
        frame.extend_from_slice(&ccp_body);
        let step = ppp.on_frame(&frame);
        assert_eq!(step.frames.len(), 1, "expected one Protocol-Reject frame");
        let (proto, code, _id, body) = peel(&step.frames[0]);
        assert_eq!(proto, ProtocolId::Lcp.as_u16());
        assert_eq!(code, LcpCode::ProtocolReject.as_u8());
        assert_eq!(&body[..2], &[0x80, 0xfd]);
        assert_eq!(&body[2..], &ccp_body);
    }

    #[test]
    fn protocol_reject_identifier_changes_per_packet() {
        let mut ppp = Ppp::new([0, 0, 0, 0], AuthMethod::Pap);
        drive_to_auth_pending(&mut ppp);
        let mut frame = vec![
            ADDRESS_ALL_STATIONS,
            CONTROL_UI,
            0x80,
            0xfd,
            0x01,
            0x01,
            0x00,
            0x04,
        ];
        let step1 = ppp.on_frame(&frame);
        frame[5] = 0x02;
        let step2 = ppp.on_frame(&frame);
        let (_, _, id1, _) = peel(&step1.frames[0]);
        let (_, _, id2, _) = peel(&step2.frames[0]);
        assert_ne!(id1, id2, "Protocol-Reject Identifier must change");
    }

    #[test]
    fn pap_request_emits_need_auth_event() {
        let mut ppp = Ppp::new([0, 0, 0, 0], AuthMethod::Pap);
        drive_to_auth_pending(&mut ppp);

        // PAP Authenticate-Request: id=2, peer-id="alice", pw="hunter2".
        let user = b"alice";
        let pw = b"hunter2";
        let mut pap_body = vec![
            pap::Code::AuthenticateRequest.as_u8(),
            2,
            0,
            0, // length placeholder
            u8::try_from(user.len()).unwrap(),
        ];
        pap_body.extend_from_slice(user);
        pap_body.push(u8::try_from(pw.len()).unwrap());
        pap_body.extend_from_slice(pw);
        let total = u16::try_from(pap_body.len()).unwrap();
        pap_body[2..4].copy_from_slice(&total.to_be_bytes());

        let frame = encode_pap_frame(&pap_body);
        let step = ppp.on_frame(&frame);

        match step.event {
            Some(PppEvent::NeedPapAuth { peer_id, password }) => {
                assert_eq!(peer_id, user);
                assert_eq!(password, pw);
            }
            other => panic!("expected NeedPapAuth, got {other:?}"),
        }
        assert!(matches!(
            ppp.phase,
            Phase::AuthInFlight {
                method: InFlightMethod::Pap { pap_id: 2 }
            }
        ));
    }

    #[test]
    fn auth_accept_acks_pap_and_starts_ipcp() {
        let mut ppp = Ppp::new([0, 0, 0, 0], AuthMethod::Pap);
        drive_to_auth_pending(&mut ppp);
        // Send a PAP request to advance to AuthInFlight.
        let pap_body = vec![
            pap::Code::AuthenticateRequest.as_u8(),
            7,
            0x00,
            0x08,
            0x01,
            b'a',
            0x01,
            b'p',
        ];
        let _ = ppp.on_frame(&encode_pap_frame(&pap_body));

        let addrs = AssignedAddrs {
            ip: [10, 0, 0, 7],
            dns1: Some([1, 1, 1, 1]),
            ..AssignedAddrs::default()
        };
        let step = ppp.on_auth_result(AuthVerdict::Accept { addrs });

        // Expect at least two frames: PAP Ack + IPCP Configure-Request.
        assert!(step.frames.len() >= 2);
        let (proto0, code0, id0, _) = peel(&step.frames[0]);
        assert_eq!(proto0, ProtocolId::Pap.as_u16());
        assert_eq!(code0, pap::Code::AuthenticateAck.as_u8());
        assert_eq!(id0, 7);
        let (proto1, code1, _, _) = peel(&step.frames[1]);
        assert_eq!(proto1, ProtocolId::Ipcp.as_u16());
        assert_eq!(code1, IpcpCode::ConfigureRequest.as_u8());
        assert!(matches!(ppp.phase, Phase::Network));
    }

    #[test]
    fn ipcp_naks_zero_ip_with_assigned() {
        let mut ppp = Ppp::new([0, 0, 0, 0], AuthMethod::Pap);
        drive_to_auth_pending(&mut ppp);
        let pap_body = vec![
            pap::Code::AuthenticateRequest.as_u8(),
            7,
            0x00,
            0x08,
            0x01,
            b'a',
            0x01,
            b'p',
        ];
        let _ = ppp.on_frame(&encode_pap_frame(&pap_body));
        let addrs = AssignedAddrs {
            ip: [10, 0, 0, 42],
            ..AssignedAddrs::default()
        };
        let _ = ppp.on_auth_result(AuthVerdict::Accept { addrs });

        // Client CR with IP-Address = 0.0.0.0.
        let opts: Vec<u8> = vec![0x03, 0x06, 0, 0, 0, 0];
        let frame = ipcp_cr(1, &opts);
        let step = ppp.on_frame(&frame);
        assert_eq!(step.frames.len(), 1);
        let (proto, code, id, body) = peel(&step.frames[0]);
        assert_eq!(proto, ProtocolId::Ipcp.as_u16());
        assert_eq!(code, IpcpCode::ConfigureNak.as_u8());
        assert_eq!(id, 1);
        // Nak body should contain IP-Address = 10.0.0.42.
        assert_eq!(body, &[0x03, 0x06, 10, 0, 0, 42]);
    }

    #[test]
    fn ipcp_acks_matching_ip() {
        let mut ppp = Ppp::new([0, 0, 0, 0], AuthMethod::Pap);
        drive_to_auth_pending(&mut ppp);
        let pap_body = vec![
            pap::Code::AuthenticateRequest.as_u8(),
            7,
            0x00,
            0x08,
            0x01,
            b'a',
            0x01,
            b'p',
        ];
        let _ = ppp.on_frame(&encode_pap_frame(&pap_body));
        let addrs = AssignedAddrs {
            ip: [10, 0, 0, 42],
            ..AssignedAddrs::default()
        };
        let _ = ppp.on_auth_result(AuthVerdict::Accept { addrs });

        let opts: Vec<u8> = vec![0x03, 0x06, 10, 0, 0, 42];
        let frame = ipcp_cr(2, &opts);
        let step = ppp.on_frame(&frame);
        let (_, code, _, body) = peel(&step.frames[0]);
        assert_eq!(code, IpcpCode::ConfigureAck.as_u8());
        assert_eq!(body, opts.as_slice());
    }

    #[test]
    fn auth_reject_emits_nak_and_terminates() {
        let mut ppp = Ppp::new([0, 0, 0, 0], AuthMethod::Pap);
        drive_to_auth_pending(&mut ppp);
        let pap_body = vec![
            pap::Code::AuthenticateRequest.as_u8(),
            3,
            0x00,
            0x08,
            0x01,
            b'a',
            0x01,
            b'p',
        ];
        let _ = ppp.on_frame(&encode_pap_frame(&pap_body));
        let step = ppp.on_auth_result(AuthVerdict::Reject {
            message: b"bad creds".to_vec(),
        });
        assert!(step.finished);
        let (proto, code, id, _) = peel(&step.frames[0]);
        assert_eq!(proto, ProtocolId::Pap.as_u16());
        assert_eq!(code, pap::Code::AuthenticateNak.as_u8());
        assert_eq!(id, 3);
        assert!(matches!(ppp.phase, Phase::Dead));
    }
}
