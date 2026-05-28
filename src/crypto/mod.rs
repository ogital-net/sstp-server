//! In-tree cryptography module. Wraps `aws-lc-sys` directly; no `ring`,
//! `rustls`, or `openssl` crate appear in the dependency tree.
//!
//! All `unsafe` lives in [`ffi`] and the per-primitive modules; each
//! `unsafe` block carries a `// SAFETY:` comment.

// Consumers land in later milestones (SSTP framing, PPP, RADIUS bridge).
#![allow(dead_code, unused_imports)]

pub mod ffi;
pub mod hash;
pub mod hmac;
pub mod rand;
pub mod tls;

pub use hash::{Sha1, Sha256};
pub use hmac::{HmacSha1, HmacSha256};
pub use rand::fill_bytes;
pub use tls::{SslContext, TlsError, TlsStream};
