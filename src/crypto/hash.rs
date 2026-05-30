//! MD5 (via `fast-md5`), SHA-1 and SHA-256 (via `aws-lc-sys`).
//!
//! MD5 is cryptographically broken and is only used here for the RADIUS
//! wire format (RFC 2865 authenticators, User-Password obfuscation). We
//! delegate it to the `fast-md5` crate (hand-written `aarch64`/`x86_64`
//! assembly, portable Rust fallback) which avoids FIPS-module overhead
//! for a non-security primitive while still being fast.
//!
//! SHA-1 / SHA-256 remain on `aws-lc-sys` (stack-allocated, no EVP
//! overhead, FIPS-validatable).

// Hash primitives kept ready for future auth methods (MS-CHAPv2
// NT-hash chain on MD5/SHA-1, Crypto Binding HLAK on SHA-256). Md5
// is consumed by `auth::accounting` via `Md5::digest`; the rest
// becomes live as those methods land.
#![allow(dead_code)]

use std::mem::MaybeUninit;

use aws_lc_sys as aws;

pub const MD5_OUTPUT_LEN: usize = fast_md5::DIGEST_LENGTH;
pub const SHA1_OUTPUT_LEN: usize = aws::SHA_DIGEST_LENGTH as usize;
pub const SHA256_OUTPUT_LEN: usize = aws::SHA256_DIGEST_LENGTH as usize;
pub const SHA384_OUTPUT_LEN: usize = aws::SHA384_DIGEST_LENGTH as usize;

// ---------------------------------------------------------------------------
// MD5 — fast-md5 backend
// ---------------------------------------------------------------------------

/// Incremental MD5 context.
///
/// Call [`update`](Self::update) one or more times, then
/// [`finish`](Self::finish). MD5 is only used for the RADIUS wire
/// format; no security properties are assumed.
pub struct Md5 {
    inner: fast_md5::Md5,
}

impl Md5 {
    pub fn new() -> Self {
        Self {
            inner: fast_md5::Md5::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finish(self) -> [u8; MD5_OUTPUT_LEN] {
        self.inner.finalize()
    }

    /// One-shot: hash `data` and return the 16-byte digest.
    pub fn digest(data: &[u8]) -> [u8; MD5_OUTPUT_LEN] {
        fast_md5::digest(data)
    }
}

impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SHA-1 / SHA-256 — aws-lc-sys backend
// ---------------------------------------------------------------------------

macro_rules! impl_hash {
    (
        $Name:ident,
        $Ctx:ty,
        $init:path,
        $update:path,
        $finalize:path,
        $oneshot:path,
        $output_len:expr
    ) => {
        pub struct $Name {
            ctx: $Ctx,
        }

        impl $Name {
            pub fn new() -> Self {
                // SAFETY: $init fully initialises every byte of the context.
                let mut ctx = MaybeUninit::<$Ctx>::uninit();
                let rc = unsafe { $init(ctx.as_mut_ptr()) };
                assert_eq!(rc, 1, concat!(stringify!($Name), "::new init failed"));
                // SAFETY: $init returned 1, so ctx is fully initialised.
                Self {
                    ctx: unsafe { ctx.assume_init() },
                }
            }

            pub fn update(&mut self, data: &[u8]) {
                if data.is_empty() {
                    return;
                }
                // SAFETY: ctx is initialised; data is a readable slice.
                let rc = unsafe {
                    $update(
                        &mut self.ctx,
                        data.as_ptr().cast::<std::ffi::c_void>(),
                        data.len(),
                    )
                };
                assert_eq!(rc, 1, concat!(stringify!($Name), "::update failed"));
            }

            pub fn finish(mut self) -> [u8; $output_len] {
                let mut out = [0u8; $output_len];
                // SAFETY: ctx is initialised; out is exactly the digest length.
                let rc = unsafe { $finalize(out.as_mut_ptr(), &mut self.ctx) };
                assert_eq!(rc, 1, concat!(stringify!($Name), "::finish failed"));
                out
            }

            /// One-shot: hash `data` and return the digest.
            pub fn digest(data: &[u8]) -> [u8; $output_len] {
                let mut out = [0u8; $output_len];
                // SAFETY: data is a readable slice; out is exactly the digest length.
                let p = unsafe { $oneshot(data.as_ptr(), data.len(), out.as_mut_ptr()) };
                assert!(!p.is_null(), concat!(stringify!($Name), "::digest failed"));
                out
            }
        }

        impl Default for $Name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

impl_hash!(
    Sha1,
    aws::SHA_CTX,
    aws::SHA1_Init,
    aws::SHA1_Update,
    aws::SHA1_Final,
    aws::SHA1,
    SHA1_OUTPUT_LEN
);
impl_hash!(
    Sha256,
    aws::SHA256_CTX,
    aws::SHA256_Init,
    aws::SHA256_Update,
    aws::SHA256_Final,
    aws::SHA256,
    SHA256_OUTPUT_LEN
);

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 1321 test vector — confirms the fast-md5 backend is wired up.
    #[test]
    fn md5_abc() {
        assert_eq!(
            Md5::digest(b"abc"),
            [
                0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
                0x7f, 0x72
            ],
        );
    }

    // RFC 3174 test vector.    #[test]
    fn sha1_abc() {
        let out = Sha1::digest(b"abc");
        let expected: [u8; 20] = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ];
        assert_eq!(out, expected);
    }

    // RFC 6234 / NIST FIPS 180-4 test vector.
    #[test]
    fn sha256_abc() {
        let out = Sha256::digest(b"abc");
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn sha256_streaming_matches_oneshot() {
        let mut h = Sha256::new();
        h.update(b"abc");
        h.update(b"def");
        let a = h.finish();
        let b = Sha256::digest(b"abcdef");
        assert_eq!(a, b);
    }
}
