//! Generic PPP Option-Negotiation Automaton ([RFC 1661] §4).
//!
//! Implements the state-transition table from §4.1 verbatim. The FSM
//! is pure logic — it owns the state, restart counter, and current
//! identifier, but it does not perform I/O, manage timers, or know
//! anything about the option set being negotiated. The driving task
//! supplies events (including pre-classified Configure-Request
//! verdicts: [`Event::RcvConfigReqGood`] vs
//! [`Event::RcvConfigReqBad`]) and consumes the [`StepOut`] action
//! set to emit packets and arm the Restart timer.
//!
//! One [`Fsm`] instance drives a single network-layer protocol: LCP,
//! IPCP, or IPV6CP. The control-protocol-specific code (which options
//! to request, which to Ack/Nak/Reject, how to render packets) lives
//! in `ppp::lcp` / `ppp::ipcp` and wraps the FSM.

// The FSM is a verbatim transcription of the RFC 1661 §4.1 state
// table; arms that share a body are kept separate so each cell of the
// spec table is grep-able by (state, event).
#![allow(
    clippy::match_same_arms,
    clippy::too_many_lines,
    clippy::struct_excessive_bools
)]

use std::time::Duration;

// --- Spec-defined defaults (RFC 1661 §4.1, §6) -----------------------------

/// Default Restart timer interval (RFC 1661 §4.1: "3 seconds").
pub const DEFAULT_RESTART: Duration = Duration::from_secs(3);
/// Default `Max-Configure` (RFC 1661 §4.1: "10 transmissions").
pub const DEFAULT_MAX_CONFIGURE: u32 = 10;
/// Default `Max-Terminate` (RFC 1661 §4.1: "2 transmissions").
pub const DEFAULT_MAX_TERMINATE: u32 = 2;
/// Default `Max-Failure` (RFC 1661 §4.1: "5 transmissions"). Used to
/// detect that the peer is rejecting everything we send.
pub const DEFAULT_MAX_FAILURE: u32 = 5;

// --- State and events (RFC 1661 §4.2) -------------------------------------

/// Automaton states from RFC 1661 §4.2. Numbering matches the spec.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// 0 — lower layer is unavailable, no Open has been issued.
    #[default]
    Initial,
    /// 1 — administrative Open issued, lower layer still down.
    Starting,
    /// 2 — lower layer is up, no Open issued.
    Closed,
    /// 3 — lower layer is up, peer has tried to negotiate (or we
    /// closed after Open).
    Stopped,
    /// 4 — Terminate-Request sent, waiting for Ack (admin close path).
    Closing,
    /// 5 — Terminate-Request sent, waiting for Ack (peer-close path).
    Stopping,
    /// 6 — Configure-Request sent, no Ack from peer yet.
    ReqSent,
    /// 7 — Configure-Ack received, but our last Configure-Request has
    /// not been Acked by the peer.
    AckRcvd,
    /// 8 — peer's Configure-Request Acked, but we have not received an
    /// Ack to ours.
    AckSent,
    /// 9 — both directions converged; this layer is up.
    Opened,
}

/// Events that drive transitions, per RFC 1661 §4.1 / §4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Lower layer reports it is up.
    Up,
    /// Lower layer reports it is down.
    #[allow(dead_code)] // FUTURE: emitted when SSTP signals lower-layer-down (today the session task tears down end-to-end).
    Down,
    /// Administrative open.
    Open,
    /// Administrative close.
    Close,
    /// Restart timer expired (delivered by the driving task).
    RestartTimeout,
    /// Receive Configure-Request; options are all acceptable.
    RcvConfigReqGood,
    /// Receive Configure-Request; at least one option must be Nak'd
    /// or Rejected. The driver decides which packet code (Nak vs Rej)
    /// to actually emit when consuming [`Action::SendConfigureNak`].
    RcvConfigReqBad,
    /// Receive Configure-Ack with our identifier and options.
    RcvConfigAck,
    /// Receive Configure-Nak or Configure-Reject for our outstanding
    /// Configure-Request. RFC 1661 merges the two as RCN because the
    /// state transitions are identical.
    RcvConfigNak,
    /// Receive Terminate-Request from peer.
    RcvTerminateReq,
    /// Receive Terminate-Ack from peer.
    RcvTerminateAck,
    /// Receive a Code-Reject (or Protocol-Reject) we tolerate — the
    /// rejected code is not catastrophic to the FSM.
    RcvCodeRejPermitted,
    /// Receive a Code-Reject (or Protocol-Reject) we cannot tolerate.
    #[allow(dead_code)] // FUTURE: emitted by the driver once Code-Reject classification (RFC 1661 §5.5) lands.
    RcvCodeRejCatastrophic,
    /// Receive an unknown packet code (drives a Code-Reject).
    RcvUnknownCode,
    /// Echo-Request, Echo-Reply or Discard-Request received (Opened
    /// only emits an Echo-Reply; in other states the FSM ignores).
    RcvEcho,
}

// --- Actions ---------------------------------------------------------------

/// Restart timer manipulation requested by the FSM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartTimer {
    /// Arm (or rearm) the Restart timer with the configured interval.
    Start,
    /// Cancel a pending Restart timer.
    Stop,
}

/// One packet the driver should emit in response to the step. RFC
/// 1661 §4.2 names the actions scr / sca / scn / str / sta / scj /
/// ser; we expose them as a tagged enum so the call site stays
/// readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Send {
    /// scr — Send Configure-Request with the FSM's current identifier
    /// (use [`Fsm::current_identifier`]).
    ConfigureRequest,
    /// sca — Send Configure-Ack echoing the request just received.
    ConfigureAck,
    /// scn — Send Configure-Nak *or* Configure-Reject; choice is the
    /// driver's based on whether the offending options were
    /// recognisable-but-unacceptable (Nak) or unrecognised (Reject).
    ConfigureNak,
    /// str — Send Terminate-Request.
    TerminateReq,
    /// sta — Send Terminate-Ack.
    TerminateAck,
    /// scj — Send Code-Reject for the offending packet.
    CodeReject,
    /// ser — Send Echo-Reply.
    EchoReply,
}

/// Higher-layer notifications (tlu / tld / tls / tlf from RFC 1661
/// §4.2). For LCP these drive transitions between the PPP phases
/// (Establish → Authenticate → Network → Terminate, RFC 1661 §3.2).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Notify {
    /// tlu — This Layer Up. For LCP this is the cue to start auth.
    pub up: bool,
    /// tld — This Layer Down. For LCP, tear down auth + NCPs.
    pub down: bool,
    /// tls — This Layer Started. Ask the lower layer to come up
    /// (no-op once TLS / SSTP is already in `Server_Call_Connected`).
    pub started: bool,
    /// tlf — This Layer Finished. Cue the driver to tear the SSTP
    /// session down.
    pub finished: bool,
}

/// Result of one FSM step.
///
/// Each cell of the RFC 1661 §4.1 table emits at most one Send
/// action and at most one Restart-timer op; multiple notifications
/// can co-occur (e.g. `tld,scr,sca/8` from Opened on RCR+ emits both
/// `tld` and two sends — handled by reusing the per-step counter
/// pattern; see [`Fsm::step`]).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StepOut {
    pub new_state: State,
    pub send: Option<Send>,
    /// Some transitions need to emit two packets (RFC 1661 §4.4: e.g.
    /// `tld,scr,sca/8` from Opened on RCR+ first sends Configure-Request
    /// to restart negotiation, then Configure-Ack for the inbound
    /// request). When `Some`, the driver writes this packet *after*
    /// `send`.
    pub send_extra: Option<Send>,
    pub restart_timer: Option<RestartTimer>,
    pub notify: Notify,
}

impl StepOut {
    fn just(new_state: State) -> Self {
        Self {
            new_state,
            ..Self::default()
        }
    }
}

// --- The state machine ----------------------------------------------------

/// Generic Option-Negotiation Automaton ([RFC 1661] §4).
#[derive(Debug)]
pub struct Fsm {
    state: State,
    /// Current packet identifier; bumped before each Configure-Request
    /// or Terminate-Request emission. RFC 1661 §6.1 ("Configure-Request",
    /// Identifier field).
    identifier: u8,
    /// Restart counter — decremented each time a Configure-Request or
    /// Terminate-Request is transmitted (RFC 1661 §4.2).
    restart_counter: u32,
    /// Failure counter for Configure-Nak loops (RFC 1661 §4.6 "Max-Failure").
    failure_counter: u32,
    max_configure: u32,
    max_terminate: u32,
    max_failure: u32,
}

impl Default for Fsm {
    fn default() -> Self {
        Self::new()
    }
}

impl Fsm {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: State::Initial,
            identifier: 0,
            restart_counter: 0,
            failure_counter: 0,
            max_configure: DEFAULT_MAX_CONFIGURE,
            max_terminate: DEFAULT_MAX_TERMINATE,
            max_failure: DEFAULT_MAX_FAILURE,
        }
    }

    #[must_use]
    #[allow(dead_code)] // FUTURE: state inspection for control-socket `show sess <id>` once exposed.
    pub fn state(&self) -> State {
        self.state
    }

    /// Identifier to stamp into the next Configure-Request /
    /// Terminate-Request the driver emits in response to [`Send`].
    #[must_use]
    #[allow(dead_code)] // FUTURE: identifier inspection for the same control-socket surface.
    pub fn current_identifier(&self) -> u8 {
        self.identifier
    }

    /// Reset Max-Failure counter at the start of a new negotiation
    /// round. RFC 1661 §4.6 leaves the exact reset rule
    /// implementation-defined; we zero it whenever the restart
    /// counter is initialised.
    fn irc_configure(&mut self) {
        self.restart_counter = self.max_configure;
        self.failure_counter = self.max_failure;
    }

    fn irc_terminate(&mut self) {
        self.restart_counter = self.max_terminate;
    }

    /// Bump the identifier ahead of the next Configure-Request or
    /// Terminate-Request. RFC 1661 §6.1 says identifiers must change
    /// "with each new request"; identical retransmissions reuse the
    /// same identifier (handled by the caller, which only bumps via
    /// this when it actually mints a new request).
    pub fn bump_identifier(&mut self) -> u8 {
        self.identifier = self.identifier.wrapping_add(1);
        self.identifier
    }

    /// Drive one event. Returns the action set the caller must
    /// execute; [`StepOut::new_state`] is the post-transition state.
    pub fn step(&mut self, event: Event) -> StepOut {
        use Event as E;
        use State as S;

        let from = self.state;
        let mut out = match (from, event) {
            // --- Up ----------------------------------------------------
            (S::Initial, E::Up) => StepOut::just(S::Closed),
            (S::Starting, E::Up) => {
                self.irc_configure();
                StepOut {
                    new_state: S::ReqSent,
                    send: Some(Send::ConfigureRequest),
                    restart_timer: Some(RestartTimer::Start),
                    ..StepOut::default()
                }
            }

            // --- Down --------------------------------------------------
            (S::Closed, E::Down) => StepOut::just(S::Initial),
            (S::Stopped, E::Down) => StepOut {
                new_state: S::Starting,
                notify: Notify {
                    started: true,
                    ..Notify::default()
                },
                ..StepOut::default()
            },
            (S::Closing, E::Down) => StepOut::just(S::Initial),
            (S::Stopping | S::ReqSent | S::AckRcvd | S::AckSent, E::Down) => {
                StepOut::just(S::Starting)
            }
            (S::Opened, E::Down) => StepOut {
                new_state: S::Starting,
                notify: Notify {
                    down: true,
                    ..Notify::default()
                },
                ..StepOut::default()
            },

            // --- Open --------------------------------------------------
            (S::Initial, E::Open) => StepOut {
                new_state: S::Starting,
                notify: Notify {
                    started: true,
                    ..Notify::default()
                },
                ..StepOut::default()
            },
            (S::Starting, E::Open) => StepOut::just(S::Starting),
            (S::Closed, E::Open) => {
                self.irc_configure();
                StepOut {
                    new_state: S::ReqSent,
                    send: Some(Send::ConfigureRequest),
                    restart_timer: Some(RestartTimer::Start),
                    ..StepOut::default()
                }
            }
            // Stopped/Closing/Stopping/ReqSent/AckRcvd/AckSent: Open is a no-op
            // (already trying to come up). Opened with Open + "r" (restart)
            // is also handled as a no-op here; an explicit restart should go
            // via Close+Open from the driver.
            (
                S::Stopped
                | S::Closing
                | S::Stopping
                | S::ReqSent
                | S::AckRcvd
                | S::AckSent
                | S::Opened,
                E::Open,
            ) => StepOut::just(from),

            // --- Close -------------------------------------------------
            (S::Initial, E::Close) => StepOut::just(S::Initial),
            (S::Starting, E::Close) => StepOut {
                new_state: S::Initial,
                notify: Notify {
                    finished: true,
                    ..Notify::default()
                },
                ..StepOut::default()
            },
            (S::Closed | S::Stopped, E::Close) => StepOut::just(S::Closed),
            (S::Closing | S::Stopping, E::Close) => StepOut::just(S::Closing),
            (S::ReqSent | S::AckRcvd | S::AckSent, E::Close) => {
                self.irc_terminate();
                StepOut {
                    new_state: S::Closing,
                    send: Some(Send::TerminateReq),
                    restart_timer: Some(RestartTimer::Start),
                    ..StepOut::default()
                }
            }
            (S::Opened, E::Close) => {
                self.irc_terminate();
                StepOut {
                    new_state: S::Closing,
                    send: Some(Send::TerminateReq),
                    restart_timer: Some(RestartTimer::Start),
                    notify: Notify {
                        down: true,
                        ..Notify::default()
                    },
                    ..StepOut::default()
                }
            }

            // --- Restart timer (TO+/TO-) ------------------------------
            // Spec splits TO+ (counter > 0) and TO- (counter == 0); the
            // FSM owns the counter, so we dispatch internally.
            (
                from @ (S::Closing | S::Stopping | S::ReqSent | S::AckRcvd | S::AckSent),
                E::RestartTimeout,
            ) => self.on_restart_timeout(from),
            // Restart timeout in any other state: spurious, ignore.
            (_, E::RestartTimeout) => StepOut::just(from),

            // --- RCR+ (good Configure-Request) ------------------------
            (S::Closed, E::RcvConfigReqGood | E::RcvConfigReqBad) => StepOut {
                new_state: S::Closed,
                send: Some(Send::TerminateAck),
                ..StepOut::default()
            },
            (S::Stopped, E::RcvConfigReqGood) => {
                self.irc_configure();
                StepOut {
                    new_state: S::AckSent,
                    send: Some(Send::ConfigureRequest),
                    send_extra: Some(Send::ConfigureAck),
                    restart_timer: Some(RestartTimer::Start),
                    ..StepOut::default()
                }
            }
            (S::Closing | S::Stopping, E::RcvConfigReqGood | E::RcvConfigReqBad) => {
                StepOut::just(from)
            }
            (S::ReqSent, E::RcvConfigReqGood) => StepOut {
                new_state: S::AckSent,
                send: Some(Send::ConfigureAck),
                ..StepOut::default()
            },
            (S::AckRcvd, E::RcvConfigReqGood) => StepOut {
                new_state: S::Opened,
                send: Some(Send::ConfigureAck),
                notify: Notify {
                    up: true,
                    ..Notify::default()
                },
                ..StepOut::default()
            },
            (S::AckSent, E::RcvConfigReqGood) => StepOut {
                new_state: S::AckSent,
                send: Some(Send::ConfigureAck),
                ..StepOut::default()
            },
            (S::Opened, E::RcvConfigReqGood) => StepOut {
                new_state: S::AckSent,
                send: Some(Send::ConfigureRequest),
                send_extra: Some(Send::ConfigureAck),
                restart_timer: Some(RestartTimer::Start),
                notify: Notify {
                    down: true,
                    ..Notify::default()
                },
            },

            // --- RCR- (bad Configure-Request) -------------------------
            (S::Stopped, E::RcvConfigReqBad) => {
                self.irc_configure();
                StepOut {
                    new_state: S::ReqSent,
                    send: Some(Send::ConfigureRequest),
                    send_extra: Some(Send::ConfigureNak),
                    restart_timer: Some(RestartTimer::Start),
                    ..StepOut::default()
                }
            }
            (S::ReqSent | S::AckSent, E::RcvConfigReqBad) => StepOut {
                new_state: S::ReqSent,
                send: Some(Send::ConfigureNak),
                ..StepOut::default()
            },
            (S::AckRcvd, E::RcvConfigReqBad) => StepOut {
                new_state: S::AckRcvd,
                send: Some(Send::ConfigureNak),
                ..StepOut::default()
            },
            (S::Opened, E::RcvConfigReqBad) => StepOut {
                new_state: S::ReqSent,
                send: Some(Send::ConfigureRequest),
                send_extra: Some(Send::ConfigureNak),
                restart_timer: Some(RestartTimer::Start),
                notify: Notify {
                    down: true,
                    ..Notify::default()
                },
            },

            // --- RCA (Configure-Ack) ----------------------------------
            (S::Closed | S::Stopped, E::RcvConfigAck) => StepOut {
                new_state: from,
                send: Some(Send::CodeReject),
                ..StepOut::default()
            },
            (S::Closing | S::Stopping, E::RcvConfigAck) => StepOut::just(from),
            (S::ReqSent, E::RcvConfigAck) => {
                self.irc_configure();
                StepOut {
                    new_state: S::AckRcvd,
                    restart_timer: Some(RestartTimer::Stop),
                    ..StepOut::default()
                }
            }
            // 6x: protocol error per RFC 1661 §4.2 — re-arm and restart.
            (S::AckRcvd, E::RcvConfigAck) => StepOut {
                new_state: S::ReqSent,
                send: Some(Send::ConfigureRequest),
                ..StepOut::default()
            },
            (S::AckSent, E::RcvConfigAck) => {
                self.irc_configure();
                StepOut {
                    new_state: S::Opened,
                    restart_timer: Some(RestartTimer::Stop),
                    notify: Notify {
                        up: true,
                        ..Notify::default()
                    },
                    ..StepOut::default()
                }
            }
            (S::Opened, E::RcvConfigAck) => StepOut {
                new_state: S::ReqSent,
                send: Some(Send::ConfigureRequest),
                notify: Notify {
                    down: true,
                    ..Notify::default()
                },
                ..StepOut::default()
            },

            // --- RCN (Configure-Nak/Reject) ---------------------------
            (S::Closed | S::Stopped, E::RcvConfigNak) => StepOut {
                new_state: from,
                send: Some(Send::CodeReject),
                ..StepOut::default()
            },
            (S::Closing | S::Stopping, E::RcvConfigNak) => StepOut::just(from),
            (S::ReqSent | S::AckSent, E::RcvConfigNak) => {
                self.irc_configure();
                StepOut {
                    new_state: from,
                    send: Some(Send::ConfigureRequest),
                    ..StepOut::default()
                }
            }
            // 6x cross-over (protocol error).
            (S::AckRcvd, E::RcvConfigNak) => StepOut {
                new_state: S::ReqSent,
                send: Some(Send::ConfigureRequest),
                ..StepOut::default()
            },
            (S::Opened, E::RcvConfigNak) => StepOut {
                new_state: S::ReqSent,
                send: Some(Send::ConfigureRequest),
                notify: Notify {
                    down: true,
                    ..Notify::default()
                },
                ..StepOut::default()
            },

            // --- RTR (Terminate-Request) ------------------------------
            (
                S::Closed
                | S::Stopped
                | S::Closing
                | S::Stopping
                | S::ReqSent
                | S::AckRcvd
                | S::AckSent,
                E::RcvTerminateReq,
            ) => StepOut {
                new_state: if matches!(from, S::Closed | S::Stopped | S::Closing | S::Stopping) {
                    from
                } else {
                    S::ReqSent
                },
                send: Some(Send::TerminateAck),
                ..StepOut::default()
            },
            (S::Opened, E::RcvTerminateReq) => {
                self.restart_counter = 0; // zrc — RFC 1661 §4.2 "zrc"
                StepOut {
                    new_state: S::Stopping,
                    send: Some(Send::TerminateAck),
                    restart_timer: Some(RestartTimer::Start),
                    notify: Notify {
                        down: true,
                        ..Notify::default()
                    },
                    ..StepOut::default()
                }
            }

            // --- RTA (Terminate-Ack) ----------------------------------
            (S::Closed | S::Stopped, E::RcvTerminateAck) => StepOut::just(from),
            (S::Closing, E::RcvTerminateAck) => StepOut {
                new_state: S::Closed,
                notify: Notify {
                    finished: true,
                    ..Notify::default()
                },
                ..StepOut::default()
            },
            (S::Stopping, E::RcvTerminateAck) => StepOut {
                new_state: S::Stopped,
                notify: Notify {
                    finished: true,
                    ..Notify::default()
                },
                ..StepOut::default()
            },
            (S::ReqSent | S::AckSent, E::RcvTerminateAck) => StepOut::just(from),
            // 6x cross-over.
            (S::AckRcvd, E::RcvTerminateAck) => StepOut::just(S::ReqSent),
            (S::Opened, E::RcvTerminateAck) => StepOut {
                new_state: S::ReqSent,
                send: Some(Send::ConfigureRequest),
                notify: Notify {
                    down: true,
                    ..Notify::default()
                },
                ..StepOut::default()
            },

            // --- RUC (unknown code) -----------------------------------
            (_, E::RcvUnknownCode) => StepOut {
                new_state: from,
                send: Some(Send::CodeReject),
                ..StepOut::default()
            },

            // --- RXJ+ (permitted Code-Reject) -------------------------
            (_, E::RcvCodeRejPermitted) => StepOut::just(from),

            // --- RXJ- (catastrophic Code-Reject) ----------------------
            (S::Closed | S::Stopped, E::RcvCodeRejCatastrophic) => StepOut {
                new_state: if from == S::Closed {
                    S::Closed
                } else {
                    S::Stopped
                },
                notify: Notify {
                    finished: true,
                    ..Notify::default()
                },
                ..StepOut::default()
            },
            (S::Closing, E::RcvCodeRejCatastrophic) => StepOut {
                new_state: S::Closed,
                notify: Notify {
                    finished: true,
                    ..Notify::default()
                },
                ..StepOut::default()
            },
            (S::Stopping | S::ReqSent | S::AckRcvd | S::AckSent, E::RcvCodeRejCatastrophic) => {
                StepOut {
                    new_state: S::Stopped,
                    notify: Notify {
                        finished: true,
                        ..Notify::default()
                    },
                    ..StepOut::default()
                }
            }
            (S::Opened, E::RcvCodeRejCatastrophic) => {
                self.irc_terminate();
                StepOut {
                    new_state: S::Stopping,
                    send: Some(Send::TerminateReq),
                    restart_timer: Some(RestartTimer::Start),
                    notify: Notify {
                        down: true,
                        ..Notify::default()
                    },
                    ..StepOut::default()
                }
            }

            // --- RXR (echo / discard) --------------------------------
            (S::Opened, E::RcvEcho) => StepOut {
                new_state: S::Opened,
                send: Some(Send::EchoReply),
                ..StepOut::default()
            },
            (_, E::RcvEcho) => StepOut::just(from),

            // Spurious events in Initial/Starting: RFC 1661 leaves
            // these as "no transition".
            (S::Initial | S::Starting, _) => StepOut::just(from),
            // Up in any non-Initial/Starting state: spurious per RFC 1661 §4.1.
            (_, E::Up) => StepOut::just(from),
        };

        // Decrement the restart counter every time we transmit a
        // Configure-Request or Terminate-Request (RFC 1661 §4.2 "scr"
        // and "str" both consume one count).
        if matches!(out.send, Some(Send::ConfigureRequest | Send::TerminateReq)) {
            self.restart_counter = self.restart_counter.saturating_sub(1);
        }
        if matches!(
            out.send_extra,
            Some(Send::ConfigureRequest | Send::TerminateReq)
        ) {
            self.restart_counter = self.restart_counter.saturating_sub(1);
        }

        out.new_state = self.state_after(out.new_state);
        self.state = out.new_state;
        out
    }

    /// Hook so future tweaks (e.g. instrumentation) have a single
    /// commit point; right now it's the identity.
    #[allow(clippy::unused_self)]
    fn state_after(&self, s: State) -> State {
        s
    }

    /// Handle restart timer expiry, splitting into TO+ vs TO- per
    /// RFC 1661 §4.2. Called from [`Self::step`].
    fn on_restart_timeout(&mut self, from: State) -> StepOut {
        use State as S;
        if self.restart_counter > 0 {
            // TO+: counter still has budget; retransmit.
            match from {
                S::Closing | S::Stopping => StepOut {
                    new_state: from,
                    send: Some(Send::TerminateReq),
                    restart_timer: Some(RestartTimer::Start),
                    ..StepOut::default()
                },
                S::ReqSent | S::AckRcvd => StepOut {
                    new_state: S::ReqSent,
                    send: Some(Send::ConfigureRequest),
                    restart_timer: Some(RestartTimer::Start),
                    ..StepOut::default()
                },
                S::AckSent => StepOut {
                    new_state: S::AckSent,
                    send: Some(Send::ConfigureRequest),
                    restart_timer: Some(RestartTimer::Start),
                    ..StepOut::default()
                },
                _ => StepOut::just(from),
            }
        } else {
            // TO-: out of budget. tlf + state transition per §4.1.
            match from {
                S::Closing => StepOut {
                    new_state: S::Closed,
                    notify: Notify {
                        finished: true,
                        ..Notify::default()
                    },
                    ..StepOut::default()
                },
                // ReqSent/AckRcvd/AckSent: drop to Stopped (the "3p"
                // marker in the §4.1 table — "passive open" remembers
                // the peer was alive).
                S::Stopping | S::ReqSent | S::AckRcvd | S::AckSent => StepOut {
                    new_state: S::Stopped,
                    notify: Notify {
                        finished: true,
                        ..Notify::default()
                    },
                    ..StepOut::default()
                },
                _ => StepOut::just(from),
            }
        }
    }
}

// --- Tests ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn opened() -> Fsm {
        // Drive a fresh FSM through the happy path to Opened.
        let mut fsm = Fsm::new();
        // Driver issues Open before lower layer comes up.
        let o = fsm.step(Event::Open);
        assert_eq!(o.new_state, State::Starting);
        assert!(o.notify.started);
        // Lower layer comes up → IRC + SCR.
        let o = fsm.step(Event::Up);
        assert_eq!(o.new_state, State::ReqSent);
        assert_eq!(o.send, Some(Send::ConfigureRequest));
        assert_eq!(o.restart_timer, Some(RestartTimer::Start));
        // Peer Acks our request → Ack-Rcvd.
        let o = fsm.step(Event::RcvConfigAck);
        assert_eq!(o.new_state, State::AckRcvd);
        assert_eq!(o.restart_timer, Some(RestartTimer::Stop));
        // Peer's Configure-Request looks fine → Opened + tlu.
        let o = fsm.step(Event::RcvConfigReqGood);
        assert_eq!(o.new_state, State::Opened);
        assert_eq!(o.send, Some(Send::ConfigureAck));
        assert!(o.notify.up);
        fsm
    }

    #[test]
    fn happy_path_to_opened() {
        let fsm = opened();
        assert_eq!(fsm.state(), State::Opened);
    }

    #[test]
    fn opened_terminate_request_goes_to_stopping() {
        let mut fsm = opened();
        let o = fsm.step(Event::RcvTerminateReq);
        assert_eq!(o.new_state, State::Stopping);
        assert_eq!(o.send, Some(Send::TerminateAck));
        assert!(o.notify.down);
        assert_eq!(o.restart_timer, Some(RestartTimer::Start));
    }

    #[test]
    fn closed_configure_request_emits_terminate_ack() {
        let mut fsm = Fsm::new();
        fsm.step(Event::Up); // Initial → Closed
        let o = fsm.step(Event::RcvConfigReqGood);
        assert_eq!(o.new_state, State::Closed);
        assert_eq!(o.send, Some(Send::TerminateAck));
    }

    #[test]
    fn close_from_opened_sends_terminate_req() {
        let mut fsm = opened();
        let o = fsm.step(Event::Close);
        assert_eq!(o.new_state, State::Closing);
        assert_eq!(o.send, Some(Send::TerminateReq));
        assert!(o.notify.down);
        assert_eq!(o.restart_timer, Some(RestartTimer::Start));
    }

    #[test]
    fn closing_terminate_ack_finishes() {
        let mut fsm = opened();
        fsm.step(Event::Close);
        let o = fsm.step(Event::RcvTerminateAck);
        assert_eq!(o.new_state, State::Closed);
        assert!(o.notify.finished);
    }

    #[test]
    fn restart_timeout_retransmits_until_exhausted() {
        let mut fsm = Fsm::new();
        fsm.max_configure = 2;
        fsm.step(Event::Open);
        fsm.step(Event::Up);
        // After SCR the counter is 1 (started at 2, one consumed).
        let o = fsm.step(Event::RestartTimeout);
        assert_eq!(o.new_state, State::ReqSent);
        assert_eq!(o.send, Some(Send::ConfigureRequest));
        // Counter now 0 → next TO is TO-.
        let o = fsm.step(Event::RestartTimeout);
        assert_eq!(o.new_state, State::Stopped);
        assert!(o.notify.finished);
    }

    #[test]
    fn rcr_in_opened_renegotiates() {
        let mut fsm = opened();
        let o = fsm.step(Event::RcvConfigReqGood);
        assert_eq!(o.new_state, State::AckSent);
        assert_eq!(o.send, Some(Send::ConfigureRequest));
        assert_eq!(o.send_extra, Some(Send::ConfigureAck));
        assert!(o.notify.down);
    }

    #[test]
    fn rcr_bad_emits_nak_or_rej() {
        let mut fsm = Fsm::new();
        fsm.step(Event::Open);
        fsm.step(Event::Up);
        let o = fsm.step(Event::RcvConfigReqBad);
        assert_eq!(o.new_state, State::ReqSent);
        assert_eq!(o.send, Some(Send::ConfigureNak));
    }

    #[test]
    fn echo_only_replies_when_opened() {
        let mut fsm = opened();
        let o = fsm.step(Event::RcvEcho);
        assert_eq!(o.send, Some(Send::EchoReply));

        let mut fsm = Fsm::new();
        fsm.step(Event::Up);
        let o = fsm.step(Event::RcvEcho);
        assert_eq!(o.send, None);
    }

    #[test]
    fn unknown_code_always_emits_code_reject() {
        let mut fsm = opened();
        let o = fsm.step(Event::RcvUnknownCode);
        assert_eq!(o.send, Some(Send::CodeReject));
        assert_eq!(o.new_state, State::Opened);
    }

    #[test]
    fn identifier_bump_wraps() {
        let mut fsm = Fsm::new();
        fsm.identifier = 0xFE;
        assert_eq!(fsm.bump_identifier(), 0xFF);
        assert_eq!(fsm.bump_identifier(), 0x00);
    }
}
