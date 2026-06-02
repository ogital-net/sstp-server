//! In-tree cryptography module. Wraps `aws-lc-sys` directly; no `ring`,
//! `rustls`, or `openssl` crate appear in the dependency tree.
//!
//! All `unsafe` lives in [`ffi`] and the per-primitive modules; each
//! `unsafe` block carries a `// SAFETY:` comment.

// Consumers land in later milestones (SSTP framing, PPP, RADIUS bridge).

pub mod ffi;
pub mod hash;
pub mod hmac;
pub mod ktls;
pub mod rand;
pub mod rekey;
pub mod tls;

/// Constant-time equality. Returns `false` immediately if the lengths
/// differ (length is not a secret), otherwise dispatches to AWS-LC's
/// `CRYPTO_memcmp` so the byte-wise comparison takes constant time
/// over equal-length inputs.
#[inline]
#[must_use]
pub fn const_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    if a.is_empty() {
        return true;
    }
    // SAFETY: both slices are non-empty and of the same length `n`;
    // CRYPTO_memcmp reads exactly `n` bytes from each pointer.
    let rc = unsafe {
        aws_lc_sys::CRYPTO_memcmp(
            a.as_ptr().cast::<std::ffi::c_void>(),
            b.as_ptr().cast::<std::ffi::c_void>(),
            a.len(),
        )
    };
    rc == 0
}

#[cfg(test)]
mod tests {
    use super::const_time_eq;

    #[test]
    fn const_time_eq_basic() {
        assert!(const_time_eq(b"", b""));
        assert!(const_time_eq(b"abc", b"abc"));
        assert!(!const_time_eq(b"abc", b"abd"));
        assert!(!const_time_eq(b"abc", b"abcd"));
        assert!(!const_time_eq(b"abcd", b""));
    }
}
