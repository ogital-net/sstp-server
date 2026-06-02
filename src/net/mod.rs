//! Listener plumbing.
//!
//! One `SO_REUSEPORT` listener socket per I/O worker thread, no
//! shared accept queue, no cross-thread coordination on the accept
//! path. The kernel hashes incoming SYNs across the listeners, so
//! the worker that accepts a connection also owns it for life.
//!
//! This module just builds the listener socket. The accept loop and
//! per-session spawn live in the `session` module.

pub mod listener;

#[allow(unused_imports)]
pub use listener::{ListenError, adopt, bind_reuseport_std};
