//! Listener plumbing.
//!
//! Per the Architecture section in `CLAUDE.md`: one `SO_REUSEPORT`
//! listener socket per I/O worker thread, no shared accept queue, no
//! cross-thread coordination on the accept path. The kernel hashes
//! incoming SYNs across the listeners, so the worker that accepts a
//! connection also owns it for life.
//!
//! This module just builds the listener socket. The accept loop and
//! per-session spawn live in M6's `session` module.

pub mod listener;

#[allow(unused_imports)]
pub use listener::{ListenError, bind_reuseport};
