//! Server-side SSTP state machine ([MS-SSTP] §3.3.1.1, §3.1.1.1).
//!
//! The state machine is pure logic: it does not perform I/O, does not
//! manage timer wheels, and does not allocate on the data path. The
//! driving task (an I/O worker in M6) feeds it [`Event`]s and consumes
//! the resulting [`StepOut`] to send bytes, arm/cancel timers, and
//! decide when to tear the connection down.
//!
//! Spec coverage:
//! * Server call-establishment FSM — §3.3.1.1.1.
//! * Shared Call-Abort and Call-Disconnect sub-FSMs — §3.1.1.1.1, §3.1.1.1.2.
//! * Hello timer — §3.1.2.3. Negotiation timer — §3.3.2.1. Abort/Disc
//!   timers — §3.1.2.1, §3.1.2.2.

// Several FSM hooks (`on_inner_auth_completed`, `set_server_cert_hash`,
// `on_hello_timeout_no_response`, `state` accessor, `Abrupt` reason)
// are spec-driven entry points that no caller exercises today —
// inner-method auth completion belongs to non-PAP futures, the cert
// hash is plumbed at construction, and abrupt teardown surfaces only
// once the data path runs over the kmod. Kept available so wiring
// them up later is a single grep.
#![allow(dead_code)]

use std::time::Duration;

use super::attr::{AttributeId, StatusCode};
use super::binding::{self, BindingOutcome, ServerBindingState};
use super::msg::{
    self, CALL_CONNECT_ACK_LEN, ControlMessage, EMPTY_CONTROL_LEN, MessageType, encode_call_abort,
    encode_call_connect_ack, encode_call_connect_nak, encode_call_disconnect, encode_empty_control,
};

// --- Spec-defined timer durations -----------------------------------------

/// §3.3.2.1: negotiation timer (60 s).
pub const TIMER_VAL_NEGOTIATION: Duration = Duration::from_secs(60);
/// §3.1.2.1: T1 — Call Abort retransmit window (3 s).
pub const TIMER_VAL_ABORT_STATE_TIMER_1: Duration = Duration::from_secs(3);
/// §3.1.2.1: T2 — Call Abort drain window (1 s).
pub const TIMER_VAL_ABORT_STATE_TIMER_2: Duration = Duration::from_secs(1);
/// §3.1.2.2: T1 — Call Disconnect ack-wait (5 s).
pub const TIMER_VAL_DISCONNECT_STATE_TIMER_1: Duration = Duration::from_secs(5);
/// §3.1.2.2: T2 — Call Disconnect drain window (1 s).
pub const TIMER_VAL_DISCONNECT_STATE_TIMER_2: Duration = Duration::from_secs(1);
/// §3.1.2.3: Hello timer interval (60 s).
pub const TIMER_VAL_HELLO: Duration = Duration::from_secs(60);

// --- State enum -----------------------------------------------------------

/// `CurrentState` values from [MS-SSTP] §3.3.1 (server) plus the
/// shared abort/disconnect substates from §3.1.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    ServerCallDisconnected,
    ServerConnectRequestPending,
    ServerCallConnectedPending,
    ServerCallConnected,
    CallAbortPending,
    CallAbortTimeoutPending,
    CallDisconnectAckPending,
    CallDisconnectTimeoutPending,
}

/// Logical timers the driving task must run on behalf of the FSM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timer {
    Negotiation,
    Hello,
    AbortT1,
    AbortT2,
    DisconnectT1,
    DisconnectT2,
}

/// Higher-layer events the state machine surfaces to the driving task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyHigher {
    /// `CALL_CONNECT_REQUEST` accepted; ask PPP to start the FSM
    /// (§3.3.5.2.2 "Request the PPP layer to start the FSM").
    StartPpp,
    /// SSTP entered `Server_Call_Connected`; PPP data frames may now
    /// flow (§3.3.5.2.3).
    SstpEstablished,
}

/// How the driving task should tear down the TCP/TLS socket once the
/// FSM terminates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Terminate {
    #[default]
    None,
    /// Clean drop — peer acknowledged disconnect or timers drained.
    Graceful,
    /// Drop the connection without sending anything (§3.1.2.3: hello
    /// timer second interval elapsed).
    Abrupt,
}

/// Output of one FSM step.
///
/// `send_len` indexes the front of the caller-supplied tx buffer; the
/// caller writes `tx[..send_len]` to the wire. `timer_stop` /
/// `timer_start` model the per-step timer ops the spec prescribes (no
/// transition in [MS-SSTP] §3.3 emits more than one of each).
#[derive(Debug, Default)]
pub struct StepOut {
    pub send_len: usize,
    pub timer_stop: Option<Timer>,
    pub timer_start: Option<(Timer, Duration)>,
    pub notify: Option<NotifyHigher>,
    pub terminate: Terminate,
}

impl StepOut {
    fn new() -> Self {
        Self::default()
    }
}

/// Reason the FSM passes through when initiating its own abort. Maps
/// directly to the Status-Info payload of the outgoing Call Abort
/// ([MS-SSTP] §2.2.13 status table).
#[derive(Debug, Clone, Copy)]
pub enum AbortReason {
    /// Server received a Call Connected with bad nonce / cert / hash
    /// algorithm / MAC (§3.3.5.2.3).
    CryptoBindingInvalid,
    /// Crypto Binding attribute missing or malformed (§3.3.5.2.3).
    CryptoBindingMissing,
    /// Negotiation timer fired before Call Connect Request or Call
    /// Connected arrived (§3.3.6.1).
    NegotiationTimeout,
    /// Out-of-state message arrived (§3.3.5.2.* "Else if `CurrentState`
    /// has any other value").
    UnexpectedMessage,
    /// No reason attribute (Call Abort with `Num Attributes = 0`).
    None,
}

impl AbortReason {
    fn to_status(self) -> Option<(u8, StatusCode)> {
        Some(match self {
            Self::CryptoBindingInvalid => (
                AttributeId::CryptoBinding.as_u8(),
                StatusCode::ValueNotSupported,
            ),
            Self::CryptoBindingMissing => (
                AttributeId::StatusInfo.as_u8(),
                StatusCode::AttribNotSupportedInMsg,
            ),
            Self::NegotiationTimeout => (
                AttributeId::StatusInfo.as_u8(),
                StatusCode::NegotiationTimeout,
            ),
            Self::UnexpectedMessage => (
                AttributeId::StatusInfo.as_u8(),
                StatusCode::UnacceptedFrameReceived,
            ),
            Self::None => return None,
        })
    }
}

// --- The state machine itself --------------------------------------------

/// Server-side SSTP state machine for a single connection.
#[derive(Debug)]
pub struct StateMachine {
    state: State,
    /// SHA-256 of the leaf TLS certificate's DER, snapshotted from the
    /// [`SslContext`](crate::crypto::tls::SslContext) at session
    /// construction. Bound into the per-connection [`ServerBindingState`]
    /// the instant `Call-Connect-Request` initialises it.
    server_cert_hash_sha256: [u8; 32],
    /// Server-generated nonce sent in Call Connect Ack. Set on
    /// `accept_connect_request`, used by Call Connected verification.
    binding: Option<ServerBindingState>,
}

impl StateMachine {
    /// Construct a fresh state machine for a freshly-accepted HTTPS
    /// connection. Per §3.3.1.1.1 the FSM begins in
    /// `Server_Call_Disconnected`; the driving task calls
    /// [`StateMachine::on_https_accepted`] once TLS finishes.
    ///
    /// `cert_hash_sha256` is the SHA-256 of the leaf TLS certificate
    /// DER ([MS-SSTP] §2.2.7); the FSM places it into the binding
    /// state when `Call-Connect-Request` arrives so the subsequent
    /// `Call-Connected` Crypto Binding can be verified.
    pub fn new(cert_hash_sha256: [u8; 32]) -> Self {
        Self {
            state: State::ServerCallDisconnected,
            server_cert_hash_sha256: cert_hash_sha256,
            binding: None,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// `New HTTPS Connection Received` event (§3.3.2.1 step 1).
    /// Transitions to `Server_Connect_Request_Pending` and arms the
    /// negotiation timer.
    pub fn on_https_accepted(&mut self) -> StepOut {
        debug_assert_eq!(self.state, State::ServerCallDisconnected);
        self.state = State::ServerConnectRequestPending;
        StepOut {
            timer_start: Some((Timer::Negotiation, TIMER_VAL_NEGOTIATION)),
            ..StepOut::new()
        }
    }

    /// Drive a received [`ControlMessage`]. `tx` is a scratch buffer
    /// into which the FSM may write a reply; it must be at least
    /// [`CALL_CONNECT_ACK_LEN`] bytes.
    #[allow(clippy::needless_pass_by_value)]
    pub fn on_message(&mut self, msg: ControlMessage<'_>, tx: &mut [u8]) -> StepOut {
        match msg {
            ControlMessage::CallConnectRequest { protocol_id } => {
                self.on_call_connect_request(protocol_id, tx)
            }
            ControlMessage::CallConnected(cb) => {
                // The full pre-MAC packet bytes are needed for Compound
                // MAC verification; the driving task passes them via
                // [`StateMachine::verify_and_advance_to_connected`].
                // Here we only structurally accept the parse and stay
                // in pending; the caller is expected to call the
                // verification entry point with the raw packet.
                self.on_call_connected_structural(cb, tx)
            }
            ControlMessage::CallDisconnect => self.on_call_disconnect(tx),
            ControlMessage::CallDisconnectAck => self.on_call_disconnect_ack(tx),
            ControlMessage::CallAbort => self.on_call_abort(tx),
            ControlMessage::EchoRequest => self.on_echo_request(tx),
            ControlMessage::EchoResponse => self.on_echo_response(tx),
            ControlMessage::Other(_) => self.unexpected(tx),
        }
    }

    /// Receive event for a raw SSTP data packet. Restarts the hello
    /// timer when in `Server_Call_Connected` (§3.1.2.3); ignored
    /// otherwise. PPP data frames are dropped pre-`Server_Call_Connected`
    /// per §3.3.5.2.3.
    pub fn on_data_packet(&mut self) -> StepOut {
        let mut out = StepOut::new();
        if self.state == State::ServerCallConnected {
            out.timer_start = Some((Timer::Hello, TIMER_VAL_HELLO));
        }
        out
    }

    /// `Inner Authentication Completed Event` from PPP (§3.3.7.1).
    /// Records the HLAK that will be used to validate Crypto Binding.
    /// No timer/state change here — that happens when Call Connected
    /// arrives.
    pub fn on_inner_auth_completed(&mut self, hlak: Option<[u8; 32]>) {
        if let Some(b) = self.binding.as_mut() {
            b.hlak = hlak;
        }
    }

    /// `Disconnect Tunnel` event from the management/PPP layer
    /// (§3.3.4): start the disconnect handshake.
    pub fn on_higher_layer_disconnect(&mut self, tx: &mut [u8]) -> StepOut {
        // §3.1.1.1.1 Call_Disconnect_In_Progress_1.
        let n = encode_call_disconnect(tx, true);
        self.state = State::CallDisconnectAckPending;
        StepOut {
            send_len: n,
            timer_start: Some((Timer::DisconnectT1, TIMER_VAL_DISCONNECT_STATE_TIMER_1)),
            ..StepOut::new()
        }
    }

    /// Timer expiry dispatcher. The driving task funnels every timer
    /// fire through this entry point.
    pub fn on_timer(&mut self, t: Timer, tx: &mut [u8]) -> StepOut {
        match t {
            Timer::Negotiation => self.start_abort(AbortReason::NegotiationTimeout, tx),
            Timer::Hello => self.on_hello_expired(tx),
            Timer::AbortT1 => {
                // No peer Call Abort within T1 — collapse straight to
                // T2 drain. (Conservative reading of §3.1.2.1: "this
                // short delay ensures both peer and far end receive
                // the Call Abort"; we already sent ours, so wait the
                // shorter T2 and then terminate.)
                self.state = State::CallAbortTimeoutPending;
                StepOut {
                    timer_start: Some((Timer::AbortT2, TIMER_VAL_ABORT_STATE_TIMER_2)),
                    ..StepOut::new()
                }
            }
            Timer::AbortT2 | Timer::DisconnectT1 | Timer::DisconnectT2 => StepOut {
                terminate: Terminate::Graceful,
                ..StepOut::new()
            },
        }
    }

    // ---- per-message handlers ------------------------------------------

    fn on_call_connect_request(&mut self, protocol_id: u16, tx: &mut [u8]) -> StepOut {
        if self.is_in_terminal_drain() {
            return StepOut::new(); // ignore
        }
        if self.state != State::ServerConnectRequestPending {
            return self.start_abort(AbortReason::UnexpectedMessage, tx);
        }
        // Validate Encapsulated-Protocol-Id == PPP (§3.3.5.2.2).
        if protocol_id != super::attr::SSTP_ENCAPSULATED_PROTOCOL_PPP {
            let n = encode_call_connect_nak(
                tx,
                AttributeId::EncapsulatedProtocolId.as_u8(),
                StatusCode::ValueNotSupported,
            );
            return StepOut {
                send_len: n,
                ..StepOut::new()
            };
        }
        // Build server nonce + accept. We default to advertising SHA256
        // only — the spec lets the server pick its supported set.
        let mut nonce = [0u8; 32];
        crate::crypto::rand::fill_bytes(slice_to_uninit_mut(&mut nonce));
        let hash_bitmask = super::attr::CERT_HASH_PROTOCOL_SHA256;
        let n = encode_call_connect_ack(tx, hash_bitmask, &nonce);
        debug_assert_eq!(n, CALL_CONNECT_ACK_LEN);
        // Stash binding state for Call Connected verification. The
        // leaf cert hash was supplied at FSM construction
        // ([`StateMachine::new`]); the binding's hash protocol field
        // commits to SHA-256 because that's the only protocol we
        // advertise above.
        self.binding = Some(ServerBindingState {
            server_nonce: nonce,
            server_cert_hash: self.server_cert_hash_sha256.to_vec(),
            server_hash_protocol_supported: hash_bitmask,
            hlak: None,
        });
        self.state = State::ServerCallConnectedPending;
        StepOut {
            send_len: n,
            timer_stop: None,
            // Negotiation timer continues to run until Call Connected
            // arrives (§3.3.2.1 step 2 — server MAY use a separate
            // timer value, but a single 60 s window is in spec).
            timer_start: None,
            notify: Some(NotifyHigher::StartPpp),
            terminate: Terminate::None,
        }
    }

    /// Inject the server certificate hash + advertised hash protocol
    /// set into the in-flight binding state. The driving task calls
    /// this after `on_call_connect_request` (or before, if the cert
    /// hash is known at construction time).
    pub fn set_server_cert_hash(&mut self, cert_hash: Vec<u8>) {
        if let Some(b) = self.binding.as_mut() {
            b.server_cert_hash = cert_hash;
        }
    }

    fn on_call_connected_structural(
        &mut self,
        cb: super::attr::CryptoBinding<'_>,
        tx: &mut [u8],
    ) -> StepOut {
        if self.is_in_terminal_drain() {
            return StepOut::new();
        }
        if self.state != State::ServerCallConnectedPending {
            return self.start_abort(AbortReason::UnexpectedMessage, tx);
        }
        // Defer to the binding verifier. The Compound MAC input
        // (`received_packet_with_zeroed_mac`) is empty here because
        // the caller will re-drive verification through
        // [`StateMachine::verify_call_connected`] once it has the raw
        // packet. We keep this path for tests / structural checks.
        let Some(state) = self.binding.as_ref() else {
            return self.start_abort(AbortReason::CryptoBindingMissing, tx);
        };
        match binding::verify(&cb, state, &[]) {
            BindingOutcome::Ok => self.advance_to_connected(),
            BindingOutcome::AttribNotSupportedInMsg => {
                self.start_abort(AbortReason::CryptoBindingMissing, tx)
            }
            BindingOutcome::ValueNotSupported => {
                self.start_abort(AbortReason::CryptoBindingInvalid, tx)
            }
        }
    }

    /// Full Crypto Binding validation entry point: the driving task
    /// supplies the raw Call Connected packet (MAC field zeroed) for
    /// the Compound MAC computation. M6 plumbs this through to the
    /// real HMAC check; today it behaves identically to the structural
    /// path above.
    pub fn verify_call_connected(
        &mut self,
        cb: super::attr::CryptoBinding<'_>,
        packet_with_zeroed_mac: &[u8],
        tx: &mut [u8],
    ) -> StepOut {
        if self.state != State::ServerCallConnectedPending {
            return self.start_abort(AbortReason::UnexpectedMessage, tx);
        }
        let Some(state) = self.binding.as_ref() else {
            return self.start_abort(AbortReason::CryptoBindingMissing, tx);
        };
        match binding::verify(&cb, state, packet_with_zeroed_mac) {
            BindingOutcome::Ok => self.advance_to_connected(),
            BindingOutcome::AttribNotSupportedInMsg => {
                self.start_abort(AbortReason::CryptoBindingMissing, tx)
            }
            BindingOutcome::ValueNotSupported => {
                self.start_abort(AbortReason::CryptoBindingInvalid, tx)
            }
        }
    }

    fn advance_to_connected(&mut self) -> StepOut {
        self.state = State::ServerCallConnected;
        StepOut {
            timer_stop: Some(Timer::Negotiation),
            timer_start: Some((Timer::Hello, TIMER_VAL_HELLO)),
            notify: Some(NotifyHigher::SstpEstablished),
            ..StepOut::new()
        }
    }

    fn on_call_disconnect(&mut self, tx: &mut [u8]) -> StepOut {
        // §3.3.5.2.5
        match self.state {
            State::CallAbortTimeoutPending
            | State::CallAbortPending
            | State::CallDisconnectTimeoutPending => StepOut::new(),
            State::CallDisconnectAckPending => {
                let n = encode_empty_control(tx, MessageType::CallDisconnectAck);
                self.state = State::CallDisconnectTimeoutPending;
                StepOut {
                    send_len: n,
                    timer_stop: Some(Timer::DisconnectT1),
                    timer_start: Some((Timer::DisconnectT2, TIMER_VAL_DISCONNECT_STATE_TIMER_2)),
                    ..StepOut::new()
                }
            }
            _ => {
                let n = encode_empty_control(tx, MessageType::CallDisconnectAck);
                self.state = State::CallDisconnectTimeoutPending;
                StepOut {
                    send_len: n,
                    timer_start: Some((Timer::DisconnectT2, TIMER_VAL_DISCONNECT_STATE_TIMER_2)),
                    ..StepOut::new()
                }
            }
        }
    }

    fn on_call_disconnect_ack(&mut self, tx: &mut [u8]) -> StepOut {
        // §3.3.5.2.6
        match self.state {
            State::CallDisconnectAckPending => {
                self.state = State::ServerCallDisconnected;
                StepOut {
                    timer_stop: Some(Timer::DisconnectT1),
                    terminate: Terminate::Graceful,
                    ..StepOut::new()
                }
            }
            State::CallAbortPending
            | State::CallAbortTimeoutPending
            | State::CallDisconnectTimeoutPending => StepOut::new(),
            _ => self.start_abort(AbortReason::UnexpectedMessage, tx),
        }
    }

    fn on_call_abort(&mut self, tx: &mut [u8]) -> StepOut {
        // §3.3.5.2.4
        match self.state {
            State::CallAbortPending => {
                self.state = State::CallAbortTimeoutPending;
                StepOut {
                    timer_stop: Some(Timer::AbortT1),
                    timer_start: Some((Timer::AbortT2, TIMER_VAL_ABORT_STATE_TIMER_2)),
                    ..StepOut::new()
                }
            }
            State::CallAbortTimeoutPending | State::CallDisconnectTimeoutPending => StepOut::new(),
            _ => {
                // Collision: peer aborted first. Respond and drain.
                let n = encode_call_abort(tx, AbortReason::None.to_status());
                self.state = State::CallAbortTimeoutPending;
                StepOut {
                    send_len: n,
                    timer_start: Some((Timer::AbortT2, TIMER_VAL_ABORT_STATE_TIMER_2)),
                    ..StepOut::new()
                }
            }
        }
    }

    fn on_echo_request(&mut self, tx: &mut [u8]) -> StepOut {
        // §3.3.5.2.7
        match self.state {
            State::ServerCallConnected => {
                let n = encode_empty_control(tx, MessageType::EchoResponse);
                StepOut {
                    send_len: n,
                    timer_start: Some((Timer::Hello, TIMER_VAL_HELLO)),
                    ..StepOut::new()
                }
            }
            State::CallAbortTimeoutPending
            | State::CallAbortPending
            | State::CallDisconnectAckPending
            | State::CallDisconnectTimeoutPending => StepOut::new(),
            _ => self.start_abort(AbortReason::UnexpectedMessage, tx),
        }
    }

    fn on_echo_response(&mut self, tx: &mut [u8]) -> StepOut {
        // §3.3.5.2.8
        match self.state {
            State::ServerCallConnected => StepOut {
                timer_start: Some((Timer::Hello, TIMER_VAL_HELLO)),
                ..StepOut::new()
            },
            State::CallAbortTimeoutPending
            | State::CallAbortPending
            | State::CallDisconnectAckPending
            | State::CallDisconnectTimeoutPending => StepOut::new(),
            _ => self.start_abort(AbortReason::UnexpectedMessage, tx),
        }
    }

    fn on_hello_expired(&mut self, tx: &mut [u8]) -> StepOut {
        // §3.1.2.3: send Echo Request; if no SSTP packet arrives
        // within the *next* interval the connection is aborted
        // *without* sending Call Abort. The driving task tracks the
        // "next interval" by re-arming the hello timer; if it fires
        // again with no intervening rx, the task calls
        // [`StateMachine::on_hello_timeout_no_response`].
        if self.state != State::ServerCallConnected {
            return StepOut::new();
        }
        let n = encode_empty_control(tx, MessageType::EchoRequest);
        StepOut {
            send_len: n,
            timer_start: Some((Timer::Hello, TIMER_VAL_HELLO)),
            ..StepOut::new()
        }
    }

    /// Driving task signal: hello-timer-2 expired without any rx
    /// activity since the Echo Request was sent. §3.1.2.3 mandates an
    /// abrupt teardown with no Call Abort.
    #[allow(clippy::unused_self)]
    pub fn on_hello_timeout_no_response(&mut self) -> StepOut {
        StepOut {
            terminate: Terminate::Abrupt,
            ..StepOut::new()
        }
    }

    fn unexpected(&mut self, tx: &mut [u8]) -> StepOut {
        self.start_abort(AbortReason::UnexpectedMessage, tx)
    }

    fn start_abort(&mut self, reason: AbortReason, tx: &mut [u8]) -> StepOut {
        // §3.1.1.1.2 Call_Abort_In_Progress_1: send abort, T1, AP.
        let n = encode_call_abort(tx, reason.to_status());
        self.state = State::CallAbortPending;
        StepOut {
            send_len: n,
            timer_start: Some((Timer::AbortT1, TIMER_VAL_ABORT_STATE_TIMER_1)),
            ..StepOut::new()
        }
    }

    fn is_in_terminal_drain(&self) -> bool {
        matches!(
            self.state,
            State::CallAbortTimeoutPending
                | State::CallAbortPending
                | State::CallDisconnectAckPending
                | State::CallDisconnectTimeoutPending
        )
    }
}

impl Default for StateMachine {
    fn default() -> Self {
        Self::new([0u8; 32])
    }
}

// `crypto::rand::fill_bytes` expects `&mut [MaybeUninit<u8>]`. The FSM
// generates the nonce into a normal stack `[u8; 32]`, so adapt with a
// safe cast — `MaybeUninit<u8>` and `u8` share layout and the slice is
// strictly written before any read.
fn slice_to_uninit_mut(buf: &mut [u8]) -> &mut [std::mem::MaybeUninit<u8>] {
    // SAFETY: `MaybeUninit<u8>` has the same layout as `u8`; we only
    // hand the slice to `RAND_bytes`, which writes every byte before
    // anyone reads from the original `&mut [u8]`.
    unsafe {
        std::slice::from_raw_parts_mut(
            buf.as_mut_ptr().cast::<std::mem::MaybeUninit<u8>>(),
            buf.len(),
        )
    }
}

// All buffers passed to the FSM must be at least this large.
pub const MIN_TX_BUF: usize = if CALL_CONNECT_ACK_LEN > EMPTY_CONTROL_LEN {
    CALL_CONNECT_ACK_LEN
} else {
    EMPTY_CONTROL_LEN
};
// Suppress dead-code on encode_call_connect_nak imports if no path
// triggers it in early M6 wiring.
#[allow(dead_code)]
fn _silence_msg_imports() {
    let _ = msg::CALL_CONNECTED_LEN;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sstp::attr::{CERT_HASH_PROTOCOL_SHA256, SSTP_ENCAPSULATED_PROTOCOL_PPP};
    use crate::sstp::frame::Packet;
    use crate::sstp::msg::parse_control;

    fn fresh_post_handshake() -> StateMachine {
        let mut sm = StateMachine::new([0u8; 32]);
        let out = sm.on_https_accepted();
        assert_eq!(sm.state(), State::ServerConnectRequestPending);
        assert_eq!(
            out.timer_start,
            Some((Timer::Negotiation, TIMER_VAL_NEGOTIATION))
        );
        sm
    }

    #[test]
    fn handshake_to_connect_pending() {
        let mut sm = fresh_post_handshake();
        let mut tx = [0u8; 128];
        let out = sm.on_message(
            ControlMessage::CallConnectRequest {
                protocol_id: SSTP_ENCAPSULATED_PROTOCOL_PPP,
            },
            &mut tx,
        );
        assert_eq!(sm.state(), State::ServerCallConnectedPending);
        assert_eq!(out.send_len, CALL_CONNECT_ACK_LEN);
        assert_eq!(out.notify, Some(NotifyHigher::StartPpp));
        // The reply parses as a valid Call Connect Ack.
        let (Packet::Control(c), _) = Packet::parse(&tx[..out.send_len]).unwrap() else {
            panic!()
        };
        assert_eq!(c.msg_type, MessageType::CallConnectAck);
    }

    #[test]
    fn rejects_non_ppp_protocol_with_nak() {
        let mut sm = fresh_post_handshake();
        let mut tx = [0u8; 128];
        let out = sm.on_message(
            ControlMessage::CallConnectRequest {
                protocol_id: 0x9999,
            },
            &mut tx,
        );
        assert_eq!(sm.state(), State::ServerConnectRequestPending); // stays
        let (Packet::Control(c), _) = Packet::parse(&tx[..out.send_len]).unwrap() else {
            panic!()
        };
        assert_eq!(c.msg_type, MessageType::CallConnectNak);
    }

    #[test]
    fn out_of_state_message_triggers_abort() {
        let mut sm = fresh_post_handshake();
        let mut tx = [0u8; 128];
        // CALL_CONNECTED before CALL_CONNECT_REQUEST_ACK exchange.
        let out = sm.on_message(ControlMessage::EchoRequest, &mut tx);
        assert_eq!(sm.state(), State::CallAbortPending);
        assert!(out.send_len >= EMPTY_CONTROL_LEN);
        assert_eq!(out.timer_start.unwrap().0, Timer::AbortT1);
    }

    #[test]
    fn negotiation_timeout_starts_abort() {
        let mut sm = fresh_post_handshake();
        let mut tx = [0u8; 128];
        let out = sm.on_timer(Timer::Negotiation, &mut tx);
        assert_eq!(sm.state(), State::CallAbortPending);
        let (Packet::Control(c), _) = Packet::parse(&tx[..out.send_len]).unwrap() else {
            panic!()
        };
        assert_eq!(c.msg_type, MessageType::CallAbort);
    }

    #[test]
    fn echo_request_when_connected_responds() {
        let mut sm = fresh_post_handshake();
        sm.state = State::ServerCallConnected; // jump for unit test
        let mut tx = [0u8; 128];
        let out = sm.on_message(ControlMessage::EchoRequest, &mut tx);
        let (Packet::Control(c), _) = Packet::parse(&tx[..out.send_len]).unwrap() else {
            panic!()
        };
        assert_eq!(c.msg_type, MessageType::EchoResponse);
        assert_eq!(out.timer_start, Some((Timer::Hello, TIMER_VAL_HELLO)));
    }

    #[test]
    fn higher_layer_disconnect_then_ack_terminates() {
        let mut sm = fresh_post_handshake();
        sm.state = State::ServerCallConnected;
        let mut tx = [0u8; 128];
        let out = sm.on_higher_layer_disconnect(&mut tx);
        assert_eq!(sm.state(), State::CallDisconnectAckPending);
        assert_eq!(
            out.timer_start,
            Some((Timer::DisconnectT1, TIMER_VAL_DISCONNECT_STATE_TIMER_1))
        );
        let out = sm.on_message(ControlMessage::CallDisconnectAck, &mut tx);
        assert_eq!(sm.state(), State::ServerCallDisconnected);
        assert_eq!(out.terminate, Terminate::Graceful);
    }

    #[test]
    fn peer_disconnect_acked_then_drain() {
        let mut sm = fresh_post_handshake();
        sm.state = State::ServerCallConnected;
        let mut tx = [0u8; 128];
        let out = sm.on_message(ControlMessage::CallDisconnect, &mut tx);
        assert_eq!(sm.state(), State::CallDisconnectTimeoutPending);
        let (Packet::Control(c), _) = Packet::parse(&tx[..out.send_len]).unwrap() else {
            panic!()
        };
        assert_eq!(c.msg_type, MessageType::CallDisconnectAck);
        assert_eq!(
            out.timer_start,
            Some((Timer::DisconnectT2, TIMER_VAL_DISCONNECT_STATE_TIMER_2))
        );
        let out = sm.on_timer(Timer::DisconnectT2, &mut tx);
        assert_eq!(out.terminate, Terminate::Graceful);
    }

    #[test]
    fn abort_collision_responds_and_drains() {
        let mut sm = fresh_post_handshake();
        sm.state = State::ServerCallConnected;
        let mut tx = [0u8; 128];
        // Peer-initiated abort (we were not in AP).
        let out = sm.on_message(ControlMessage::CallAbort, &mut tx);
        assert_eq!(sm.state(), State::CallAbortTimeoutPending);
        let (Packet::Control(c), _) = Packet::parse(&tx[..out.send_len]).unwrap() else {
            panic!()
        };
        assert_eq!(c.msg_type, MessageType::CallAbort);
        let out = sm.on_timer(Timer::AbortT2, &mut tx);
        assert_eq!(out.terminate, Terminate::Graceful);
    }

    #[test]
    fn call_connected_with_bad_cert_aborts() {
        let mut sm = fresh_post_handshake();
        let mut tx = [0u8; 128];
        let _ = sm.on_message(
            ControlMessage::CallConnectRequest {
                protocol_id: SSTP_ENCAPSULATED_PROTOCOL_PPP,
            },
            &mut tx,
        );
        // Inject the "real" server cert hash.
        sm.set_server_cert_hash(vec![0x11u8; 32]);
        // Build a Call Connected with a *wrong* cert hash.
        let mut buf = [0u8; CALL_CONNECTED_LEN_LOCAL];
        crate::sstp::msg::encode_call_connected_pre_mac(
            &mut buf,
            CERT_HASH_PROTOCOL_SHA256,
            &sm.binding.as_ref().unwrap().server_nonce,
            &[0x22u8; 32],
        );
        let (Packet::Control(c), _) = Packet::parse(&buf).unwrap() else {
            panic!()
        };
        let cm = parse_control(c).unwrap();
        let out = sm.on_message(cm, &mut tx);
        assert_eq!(sm.state(), State::CallAbortPending);
        let (Packet::Control(c), _) = Packet::parse(&tx[..out.send_len]).unwrap() else {
            panic!()
        };
        assert_eq!(c.msg_type, MessageType::CallAbort);
    }

    // Local re-export so the test file doesn't depend on the public name.
    const CALL_CONNECTED_LEN_LOCAL: usize = crate::sstp::msg::CALL_CONNECTED_LEN;

    #[test]
    fn call_connected_with_valid_binding_advances_to_connected() {
        use crate::crypto::hmac::{HmacSha256, prf_plus_sha256_cmk};
        use crate::sstp::binding::CMK_SEED;
        use crate::sstp::msg::{encode_call_connected_pre_mac, install_compound_mac};

        let cert_hash = [0xabu8; 32];
        let mut sm = StateMachine::new(cert_hash);
        let _ = sm.on_https_accepted();
        let mut tx = [0u8; 128];
        let _ = sm.on_message(
            ControlMessage::CallConnectRequest {
                protocol_id: SSTP_ENCAPSULATED_PROTOCOL_PPP,
            },
            &mut tx,
        );
        assert_eq!(sm.state(), State::ServerCallConnectedPending);

        let nonce = sm.binding.as_ref().unwrap().server_nonce;
        let mut buf = [0u8; CALL_CONNECTED_LEN_LOCAL];
        encode_call_connected_pre_mac(&mut buf, CERT_HASH_PROTOCOL_SHA256, &nonce, &cert_hash);
        // HLAK = zeros (no inner-method MSK / PAP path).
        let hlak = [0u8; 32];
        let cmk = prf_plus_sha256_cmk(&hlak, CMK_SEED);
        let mac = HmacSha256::oneshot(&cmk, &buf);
        // Parse the *zeroed-MAC* form for the Crypto Binding view,
        // then hand the matching MAC-zeroed bytes to verify.
        let zeroed = buf;
        install_compound_mac(&mut buf, &mac);
        let (Packet::Control(c), _) = Packet::parse(&buf).unwrap() else {
            panic!()
        };
        let ControlMessage::CallConnected(cb) = parse_control(c).unwrap() else {
            panic!("not call connected")
        };
        let out = sm.verify_call_connected(cb, &zeroed, &mut tx);
        assert_eq!(sm.state(), State::ServerCallConnected);
        assert_eq!(out.notify, Some(NotifyHigher::SstpEstablished));
        assert_eq!(out.timer_stop, Some(Timer::Negotiation));
        assert_eq!(out.timer_start, Some((Timer::Hello, TIMER_VAL_HELLO)));
    }
}
