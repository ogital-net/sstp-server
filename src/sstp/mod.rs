//! SSTP wire-format codec and control-message types.
//!
//! Implements the framing described in [MS-SSTP] §2.2. The parser is
//! zero-copy: `Packet::parse` borrows directly from the input slice and
//! returns views that point into it. Encoders write into caller-supplied
//! `&mut [u8]` buffers and return the number of bytes written, so the
//! caller controls all allocation.
//!
//! Spec citations in this module refer to MS-SSTP-spec.md.

#![allow(dead_code, unused_imports)]

pub mod attr;
pub mod binding;
pub mod frame;
pub mod msg;
pub mod preamble;
pub mod state;

pub use attr::{AttrIter, Attribute, AttributeId, CryptoBinding, CryptoBindingReq, StatusInfo};
pub use frame::{ControlPacket, Packet, ParseError, SSTP_HEADER_LEN, SSTP_VERSION_1_0};
pub use msg::{ControlMessage, MessageType, parse_control, parse_control_payload};
pub use state::{State, StateMachine, StepOut, Timer};
