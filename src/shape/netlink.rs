//! Minimal `NETLINK_ROUTE` client for `tc` operations.
//!
//! Sister of [`crate::kppp::netlink`], scoped to the
//! `RTM_*QDISC` / `RTM_*TCLASS` / `RTM_*TFILTER` message types.
//! The wire-format builder ([`MessageBuf`]) and socket primitives
//! live in [`crate::netlink`]; this module is a thin tc-flavoured
//! façade over them.
//!
//! ## Scope
//!
//! Today: send a single message + read its `NLMSG_ERROR` ack.
//! Sufficient for `RTM_NEWQDISC` (HTB root install),
//! `RTM_NEWTCLASS` (HTB leaf class install), and
//! `RTM_NEWTFILTER` (ingress policer).
//!
//! FUTURE: dump (`NLM_F_DUMP`) responses for `Shaper::clear` to
//! enumerate already-installed qdiscs.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

use std::collections::HashSet;
use std::io;

use super::ShapeError;
use crate::netlink::{self as wire, DrainError, NetlinkSocket};

// Re-exports for callers in `super::mod`. Keeping these names live
// at this module path means encoder code that imports
// `netlink::MessageBuf` / `netlink::NLM_F_*` keeps compiling.
pub use crate::netlink::MessageBuf;
pub use crate::netlink::{NLM_F_ACK, NLM_F_CREATE, NLM_F_REPLACE, NLM_F_REQUEST};

/// `NETLINK_ROUTE` socket scoped to traffic-control work. One
/// request → one ack at a time; never used to dump.
#[derive(Debug)]
pub struct TcNetlink {
    sock: NetlinkSocket,
    seq: u32,
}

impl TcNetlink {
    pub fn open() -> Result<Self, ShapeError> {
        let sock = NetlinkSocket::open(libc::NETLINK_ROUTE).map_err(ShapeError::Netlink)?;
        Ok(Self { sock, seq: 1 })
    }

    /// Allocate the next sequence number for the netlink header.
    pub fn next_seq(&mut self) -> u32 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    /// Send a fully-built request (already finalized via
    /// [`MessageBuf::finalize`]) and read its single-message ack.
    /// Maps the kernel's `-errno` payload onto
    /// [`ShapeError::Kernel`].
    pub fn exchange(&self, op: &'static str, buf: &MessageBuf) -> Result<(), ShapeError> {
        self.sock.send(buf.bytes()).map_err(ShapeError::Netlink)?;

        let mut reply = [0u8; 4096];
        let received = self
            .sock
            .recv_into(&mut reply)
            .map_err(ShapeError::Netlink)?;

        let mut remaining: HashSet<u32> = [buf.seq()].into_iter().collect();
        match wire::drain_acks(received, &mut remaining) {
            Ok(()) if remaining.is_empty() => Ok(()),
            Ok(()) => Err(ShapeError::Netlink(io::Error::other(format!(
                "{op}: no NLMSG_ERROR ack for seq {}",
                buf.seq()
            )))),
            Err(DrainError::Truncated) => Err(ShapeError::Netlink(io::Error::other(
                "truncated netlink ack",
            ))),
            Err(DrainError::Kernel(errno)) => Err(ShapeError::Kernel { op, errno }),
        }
    }
}
