//! TLS 1.3 post-handshake rekey state machine (pure logic).
//!
//! Drives the userspace half of the rekey decision when the kmod
//! surfaces `SSTP_EVT_TLS_REKEY_NEEDED`. No socket I/O, no async,
//! no allocations on the hot path — just an enum of inputs, a small
//! state field, and an exhaustive transition table.
//!
//! ## Current contract: rekey is fatal
//!
//! [`kmod/sstp_demux.c`](../../kmod/sstp_demux.c) classifies any TLS
//! record whose `TLS_GET_RECORD_TYPE` cmsg is non-`application_data`,
//! emits `SSTP_EVT_TLS_REKEY_NEEDED` with the 1-byte content type
//! in `ev.arg`, sets `closing = true`, and returns `-EPIPE`. The
//! `SSTP_IOC_REKEY_TX` / `SSTP_IOC_REKEY_RX` ioctls are `-ENOSYS`
//! stubs and **not planned for the v0.x series**
//! ([`kmod/sstp_event.c`](../../kmod/sstp_event.c)). The session
//! tears down on every flavour of post-handshake TLS record.
//!
//! This matches HAProxy's AWS-LC + kTLS posture: HAProxy's vanilla
//! OpenSSL build supports cooperative rekey via `BIO_CTRL_SET_KTLS`
//! (OpenSSL drives the dance internally), but the AWS-LC /
//! BoringSSL build classifies any non-`application_data` record
//! post-handshake as fatal. We use AWS-LC for the same reasons
//! HAProxy does, and inherit the same constraint.
//!
//! Server-side `NewSessionTicket` emission is suppressed at handshake
//! time via `SSL_CTX_set_num_tickets(0)` + `SSL_OP_NO_TICKET` (see
//! [`src/crypto/tls.rs`](../tls.rs)), so the only realistic
//! `REKEY_NEEDED` causes from a healthy peer are TLS 1.3 `KeyUpdate`
//! and a fatal alert.
//!
//! ## What the FSM is for
//!
//! Despite rekey being fatal, the FSM exists to:
//!
//! 1. Decode the content type and produce a metric-friendly label
//!    (`record_type=handshake|alert|...`) so operators can tell why
//!    a session went away in the logs.
//! 2. Drive per-record-type teardown counters (`sstp_session_teardown_
//!    rekey_{handshake,alert,other}` in [`crate::metrics`]).
//! 3. Hold the door open for a future minor that revisits cooperative
//!    rekey if long-running tunnels start hitting the AES-GCM per-key
//!    record-count ceiling. The cooperative-rekey transition table
//!    is locked in with unit tests; if the policy is ever
//!    implemented in the kmod, the wire-up here would be mechanical.
//!    Until then [`decide_v03_kmod`] is the adapter the session
//!    driver calls and it always returns [`Action::TearDown`].

#![allow(dead_code)] // some variants are only reachable from the cooperative-rekey unit tests

/// TLS record content type byte (RFC 8446 §B.1). Only the variants
/// the kmod can forward via the `TLS_GET_RECORD_TYPE` cmsg are named;
/// everything else falls into `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsContentType {
    /// `0x14` (20). TLS 1.3 ignores `ChangeCipherSpec` at the record
    /// layer; the kmod should never surface one of these.
    ChangeCipherSpec,
    /// `0x15` (21). The kmod has a separate `SSTP_EVT_TLS_FATAL_ALERT`
    /// event; an `Alert` reaching this path is defensive coverage
    /// only.
    Alert,
    /// `0x16` (22). `KeyUpdate` / `NewSessionTicket` / unexpected
    /// post-handshake. The actual handshake message type lives
    /// inside the encrypted record, not the cmsg, so today's UAPI
    /// cannot distinguish them further.
    Handshake,
    /// `0x17` (23). Should never appear here — `application_data`
    /// records are the only ones the kmod hands to `ppp_input`
    /// directly.
    ApplicationData,
    /// Anything else. A real TLS peer would never emit this; treat
    /// as malformed.
    Other(u8),
}

impl TlsContentType {
    #[inline]
    #[must_use]
    pub const fn from_u8(b: u8) -> Self {
        match b {
            20 => Self::ChangeCipherSpec,
            21 => Self::Alert,
            22 => Self::Handshake,
            23 => Self::ApplicationData,
            n => Self::Other(n),
        }
    }

    /// Stable label for logs and metric names. Lower-case
    /// snake-style so it's a usable suffix for
    /// `sstp_session_teardown_rekey_<label>`.
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ChangeCipherSpec => "change_cipher_spec",
            Self::Alert => "alert",
            Self::Handshake => "handshake",
            Self::ApplicationData => "application_data",
            Self::Other(_) => "other",
        }
    }
}

/// Direction(s) of a kTLS key reinstall. `KeyUpdate`'s
/// `update_requested` flag controls whether the peer expects us to
/// roll our send keys too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Rx,
    Tx,
    Both,
}

/// Inputs to the FSM. Only [`RekeyEvent::KmodSignalled`] is wired
/// up at runtime; the rest model the cooperative-rekey design that
/// would apply if a future minor revisits the position. They
/// remain test-covered so the policy table stays correct if the
/// kmod side is ever implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekeyEvent {
    /// `SSTP_EVT_TLS_REKEY_NEEDED` from the kmod, carrying the TLS
    /// record content type byte from `TLS_GET_RECORD_TYPE`.
    KmodSignalled(TlsContentType),
    /// (cooperative-rekey design) Userspace successfully read the
    /// next handshake record off the TLS stream and identified it as
    /// a `KeyUpdate`. The boolean is RFC 8446 §4.6.3's
    /// `update_requested`.
    KeyUpdate { update_requested: bool },
    /// (cooperative-rekey design) Userspace identified the record as
    /// a `NewSessionTicket`. We never emit them server-side;
    /// receiving one means a confused peer.
    NewSessionTicket,
    /// (cooperative-rekey design) The reinstall ioctls returned 0
    /// — kmod resumed.
    KmodReinstallAcked(Direction),
    /// (cooperative-rekey design) The reinstall ioctls failed. Fatal.
    KmodReinstallFailed(Direction),
}

/// Outputs of the FSM. The session driver maps these onto socket /
/// ioctl operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Pull the next TLS record from the userspace TLS stream and
    /// re-feed the FSM with [`RekeyEvent::KeyUpdate`] /
    /// [`RekeyEvent::NewSessionTicket`].
    PullNextRecord,
    /// Re-derive traffic secret(s) via the TLS exporter and install
    /// them through `SSTP_IOC_REKEY_TX` / `SSTP_IOC_REKEY_RX`.
    InstallNewKeys(Direction),
    /// No-op. The peer asked us to resume something we never
    /// stopped doing; drain it and stay in the current state.
    Ignore,
    /// Drop the event silently (e.g. a redundant signal arrives
    /// while a rekey is already in flight). Distinct from `Ignore`
    /// only for telemetry.
    Refuse,
    /// Tear the session down. Reason is stable label material.
    TearDown { reason: TearDownReason },
}

/// Why the FSM gave up on the session. The labels are part of the
/// metrics surface — operators grep for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TearDownReason {
    /// Content type the peer should never have sent at this point
    /// (`ChangeCipherSpec`, `ApplicationData` via the rekey path, or
    /// any byte not in the RFC 8446 enum).
    UnexpectedRecord,
    /// TLS `Alert` reached the rekey classifier rather than
    /// `TLS_FATAL_ALERT`. Treat as fatal regardless of severity bit
    /// — we cannot decode the alert body without the next-record
    /// machinery.
    AlertRecord,
    /// Handshake record arrived but its msg type is not
    /// `KeyUpdate` / `NewSessionTicket`. RFC 8446 §4 forbids any
    /// other post-handshake handshake message in the data phase.
    UnexpectedHandshake,
    /// `SSTP_IOC_REKEY_*` returned a hard error.
    KmodReinstallFailed,
    /// `v0.x` kmod cannot pause; even a benign `KeyUpdate` is fatal.
    /// Matches HAProxy's AWS-LC + kTLS posture; revisit if long-
    /// lived tunnels start hitting AES-GCM record-count ceilings.
    V03KmodCannotResume,
}

impl TearDownReason {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::UnexpectedRecord => "unexpected_record",
            Self::AlertRecord => "alert_record",
            Self::UnexpectedHandshake => "unexpected_handshake",
            Self::KmodReinstallFailed => "kmod_reinstall_failed",
            Self::V03KmodCannotResume => "v03_kmod_cannot_resume",
        }
    }
}

/// State of the rekey co-routine. `Idle` is the steady state; the
/// other variants exist so a second `KmodSignalled` arriving mid-
/// rekey is `Refuse`d rather than re-driving the dance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RekeyState {
    #[default]
    Idle,
    AwaitingRecord,
    InstallingKeys(Direction),
}

/// Cooperative-rekey policy table. Pure: no I/O, no allocation.
/// This function is exercised only by unit tests; the runtime path
/// always goes through [`decide_v03_kmod`], which short-circuits to
/// [`Action::TearDown`]. Kept here so the cooperative-rekey design
/// stays test-covered against future revisits.
#[must_use]
pub fn decide(state: &mut RekeyState, event: RekeyEvent) -> Action {
    match (*state, event) {
        // Fresh signal from a quiescent session.
        (RekeyState::Idle, RekeyEvent::KmodSignalled(TlsContentType::Handshake)) => {
            *state = RekeyState::AwaitingRecord;
            Action::PullNextRecord
        }
        (RekeyState::Idle, RekeyEvent::KmodSignalled(TlsContentType::Alert)) => {
            // Stays Idle — caller tears down anyway.
            Action::TearDown {
                reason: TearDownReason::AlertRecord,
            }
        }
        (
            RekeyState::Idle,
            RekeyEvent::KmodSignalled(
                TlsContentType::ChangeCipherSpec
                | TlsContentType::ApplicationData
                | TlsContentType::Other(_),
            ),
        ) => Action::TearDown {
            reason: TearDownReason::UnexpectedRecord,
        },

        // Userspace identified the next handshake record.
        (RekeyState::AwaitingRecord, RekeyEvent::KeyUpdate { update_requested }) => {
            let dir = if update_requested {
                Direction::Both
            } else {
                Direction::Rx
            };
            *state = RekeyState::InstallingKeys(dir);
            Action::InstallNewKeys(dir)
        }
        (RekeyState::AwaitingRecord, RekeyEvent::NewSessionTicket) => {
            // We never asked for one; drop it and keep running.
            *state = RekeyState::Idle;
            Action::Ignore
        }

        // Reinstall outcomes.
        (RekeyState::InstallingKeys(expected), RekeyEvent::KmodReinstallAcked(got))
            if expected == got =>
        {
            *state = RekeyState::Idle;
            Action::Ignore
        }
        (RekeyState::InstallingKeys(_), RekeyEvent::KmodReinstallFailed(_)) => {
            *state = RekeyState::Idle;
            Action::TearDown {
                reason: TearDownReason::KmodReinstallFailed,
            }
        }

        // Mid-rekey duplicate signal, mismatched ack, or any other
        // out-of-sequence event: refuse rather than panic. The
        // session driver retains the option to tear down.
        _ => Action::Refuse,
    }
}

/// Adapter for the v0.3 kmod: every signalled record ends the
/// session. The state field is left untouched so callers don't have
/// to special-case ownership; the FSM never advances past `Idle`
/// today.
#[must_use]
pub fn decide_v03_kmod(ct: TlsContentType) -> Action {
    match ct {
        TlsContentType::Handshake => Action::TearDown {
            reason: TearDownReason::V03KmodCannotResume,
        },
        TlsContentType::Alert => Action::TearDown {
            reason: TearDownReason::AlertRecord,
        },
        TlsContentType::ChangeCipherSpec
        | TlsContentType::ApplicationData
        | TlsContentType::Other(_) => Action::TearDown {
            reason: TearDownReason::UnexpectedRecord,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_type_decode_covers_iana_values() {
        assert_eq!(
            TlsContentType::from_u8(20),
            TlsContentType::ChangeCipherSpec
        );
        assert_eq!(TlsContentType::from_u8(21), TlsContentType::Alert);
        assert_eq!(TlsContentType::from_u8(22), TlsContentType::Handshake);
        assert_eq!(TlsContentType::from_u8(23), TlsContentType::ApplicationData);
        assert_eq!(TlsContentType::from_u8(0), TlsContentType::Other(0));
        assert_eq!(TlsContentType::from_u8(99), TlsContentType::Other(99));
    }

    #[test]
    fn labels_are_metric_safe() {
        for ct in [
            TlsContentType::ChangeCipherSpec,
            TlsContentType::Alert,
            TlsContentType::Handshake,
            TlsContentType::ApplicationData,
            TlsContentType::Other(7),
        ] {
            let l = ct.label();
            assert!(!l.is_empty());
            assert!(l.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
        }
    }

    // ---- v0.3 adapter --------------------------------------------------

    #[test]
    fn v03_handshake_tears_down_with_v03_label() {
        assert_eq!(
            decide_v03_kmod(TlsContentType::Handshake),
            Action::TearDown {
                reason: TearDownReason::V03KmodCannotResume
            }
        );
    }

    #[test]
    fn v03_alert_tears_down_as_alert() {
        assert_eq!(
            decide_v03_kmod(TlsContentType::Alert),
            Action::TearDown {
                reason: TearDownReason::AlertRecord
            }
        );
    }

    #[test]
    fn v03_unexpected_records_tear_down() {
        for ct in [
            TlsContentType::ChangeCipherSpec,
            TlsContentType::ApplicationData,
            TlsContentType::Other(0),
            TlsContentType::Other(99),
        ] {
            assert_eq!(
                decide_v03_kmod(ct),
                Action::TearDown {
                    reason: TearDownReason::UnexpectedRecord
                },
                "ct={ct:?}"
            );
        }
    }

    // ---- cooperative-rekey FSM ----------------------------------------

    #[test]
    fn idle_handshake_pulls_next_record_and_advances() {
        let mut s = RekeyState::Idle;
        assert_eq!(
            decide(&mut s, RekeyEvent::KmodSignalled(TlsContentType::Handshake)),
            Action::PullNextRecord
        );
        assert_eq!(s, RekeyState::AwaitingRecord);
    }

    #[test]
    fn idle_alert_tears_down() {
        let mut s = RekeyState::Idle;
        assert_eq!(
            decide(&mut s, RekeyEvent::KmodSignalled(TlsContentType::Alert)),
            Action::TearDown {
                reason: TearDownReason::AlertRecord
            }
        );
        assert_eq!(s, RekeyState::Idle);
    }

    #[test]
    fn idle_application_data_tears_down_unexpected() {
        let mut s = RekeyState::Idle;
        assert_eq!(
            decide(
                &mut s,
                RekeyEvent::KmodSignalled(TlsContentType::ApplicationData)
            ),
            Action::TearDown {
                reason: TearDownReason::UnexpectedRecord
            }
        );
    }

    #[test]
    fn key_update_without_request_installs_rx_only() {
        let mut s = RekeyState::AwaitingRecord;
        assert_eq!(
            decide(
                &mut s,
                RekeyEvent::KeyUpdate {
                    update_requested: false
                }
            ),
            Action::InstallNewKeys(Direction::Rx)
        );
        assert_eq!(s, RekeyState::InstallingKeys(Direction::Rx));
    }

    #[test]
    fn key_update_with_request_installs_both_directions() {
        let mut s = RekeyState::AwaitingRecord;
        assert_eq!(
            decide(
                &mut s,
                RekeyEvent::KeyUpdate {
                    update_requested: true
                }
            ),
            Action::InstallNewKeys(Direction::Both)
        );
        assert_eq!(s, RekeyState::InstallingKeys(Direction::Both));
    }

    #[test]
    fn new_session_ticket_is_ignored_and_resets_to_idle() {
        let mut s = RekeyState::AwaitingRecord;
        assert_eq!(decide(&mut s, RekeyEvent::NewSessionTicket), Action::Ignore);
        assert_eq!(s, RekeyState::Idle);
    }

    #[test]
    fn matching_ack_returns_to_idle() {
        let mut s = RekeyState::InstallingKeys(Direction::Rx);
        assert_eq!(
            decide(&mut s, RekeyEvent::KmodReinstallAcked(Direction::Rx)),
            Action::Ignore
        );
        assert_eq!(s, RekeyState::Idle);
    }

    #[test]
    fn mismatched_ack_is_refused() {
        let mut s = RekeyState::InstallingKeys(Direction::Both);
        assert_eq!(
            decide(&mut s, RekeyEvent::KmodReinstallAcked(Direction::Rx)),
            Action::Refuse
        );
        assert_eq!(s, RekeyState::InstallingKeys(Direction::Both));
    }

    #[test]
    fn reinstall_failure_tears_down() {
        let mut s = RekeyState::InstallingKeys(Direction::Both);
        assert_eq!(
            decide(&mut s, RekeyEvent::KmodReinstallFailed(Direction::Both)),
            Action::TearDown {
                reason: TearDownReason::KmodReinstallFailed
            }
        );
        assert_eq!(s, RekeyState::Idle);
    }

    #[test]
    fn double_signal_mid_rekey_is_refused() {
        let mut s = RekeyState::AwaitingRecord;
        assert_eq!(
            decide(&mut s, RekeyEvent::KmodSignalled(TlsContentType::Handshake)),
            Action::Refuse
        );
        assert_eq!(s, RekeyState::AwaitingRecord);

        let mut s = RekeyState::InstallingKeys(Direction::Rx);
        assert_eq!(
            decide(&mut s, RekeyEvent::KmodSignalled(TlsContentType::Handshake)),
            Action::Refuse
        );
        assert_eq!(s, RekeyState::InstallingKeys(Direction::Rx));
    }

    #[test]
    fn full_happy_path_round_trip() {
        let mut s = RekeyState::default();
        // 1. kmod surfaces a handshake record.
        assert_eq!(
            decide(&mut s, RekeyEvent::KmodSignalled(TlsContentType::Handshake)),
            Action::PullNextRecord
        );
        // 2. userspace decoded it as KeyUpdate(update_requested=true).
        assert_eq!(
            decide(
                &mut s,
                RekeyEvent::KeyUpdate {
                    update_requested: true
                }
            ),
            Action::InstallNewKeys(Direction::Both)
        );
        // 3. kmod acks both directions.
        assert_eq!(
            decide(&mut s, RekeyEvent::KmodReinstallAcked(Direction::Both)),
            Action::Ignore
        );
        assert_eq!(s, RekeyState::Idle);

        // And we can do it again.
        assert_eq!(
            decide(&mut s, RekeyEvent::KmodSignalled(TlsContentType::Handshake)),
            Action::PullNextRecord
        );
    }

    #[test]
    fn nst_followed_by_real_keyupdate_works() {
        let mut s = RekeyState::default();
        let _ = decide(&mut s, RekeyEvent::KmodSignalled(TlsContentType::Handshake));
        let _ = decide(&mut s, RekeyEvent::NewSessionTicket); // ignore, back to Idle
        assert_eq!(s, RekeyState::Idle);

        // A subsequent real KeyUpdate works.
        let _ = decide(&mut s, RekeyEvent::KmodSignalled(TlsContentType::Handshake));
        assert_eq!(
            decide(
                &mut s,
                RekeyEvent::KeyUpdate {
                    update_requested: false
                }
            ),
            Action::InstallNewKeys(Direction::Rx)
        );
    }
}
