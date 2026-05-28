//! SHA-1 and SHA-256 using stack-allocated `SHA_CTX` / `SHA256_CTX`.
//!
//! No heap allocation per digest; the context lives entirely on the stack.
//! Uses the lower-level `SHA1_Init` / `SHA256_Init` family directly rather
//! than routing through the higher-level `EVP_MD_CTX` machinery.

use std::mem::MaybeUninit;

use aws_lc_sys as aws;

pub const SHA1_OUTPUT_LEN: usize = aws::SHA_DIGEST_LENGTH as usize;
pub const SHA256_OUTPUT_LEN: usize = aws::SHA256_DIGEST_LENGTH as usize;

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
                Self { ctx: unsafe { ctx.assume_init() } }
            }

            pub fn update(&mut self, data: &[u8]) {
                if data.is_empty() {
                    return;
                }
                // SAFETY: ctx is initialised; data is a readable slice.
                let rc =
                    unsafe { $update(&mut self.ctx, data.as_ptr().cast::<std::ffi::c_void>(), data.len()) };
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
            ///
            /// Uses the single-call FFI function directly, avoiding the
            /// Init → Update → Final round-trip across the FFI boundary.
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

    // RFC 3174 test vector.
    #[test]
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
