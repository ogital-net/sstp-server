//! HMAC-SHA1, HMAC-SHA256 and HMAC-SHA384 using stack-allocated `HMAC_CTX`.
//!
//! `HMAC_CTX_init` / `HMAC_CTX_cleanup` are used for the incremental API so
//! the context lives on the stack without a heap round-trip.  The one-shot
//! path calls the single `HMAC()` FFI function directly.

// Each `impl_hmac!` instance generates the full `new` / `update` /
// `finish` / `oneshot` quartet; concrete callers use either the
// streaming triplet (HmacSha384, ktls KDF) or the one-shot
// (HmacSha1 / HmacSha256, Crypto Binding) but not both. The unused
// arm of each instance is dead.
#![allow(dead_code)]

use std::mem::MaybeUninit;

use aws_lc_sys as aws;

use super::hash::{SHA1_OUTPUT_LEN, SHA256_OUTPUT_LEN, SHA384_OUTPUT_LEN};

macro_rules! impl_hmac {
    (
        $Name:ident,
        $evp_md:path,
        $output_len:expr
    ) => {
        pub struct $Name {
            ctx: aws::HMAC_CTX,
        }

        impl Drop for $Name {
            fn drop(&mut self) {
                // SAFETY: ctx was initialised by HMAC_CTX_init; cleanup frees
                // the inner EVP_MD_CTX state without freeing the struct itself.
                unsafe { aws::HMAC_CTX_cleanup(&mut self.ctx) };
            }
        }

        impl $Name {
            pub fn new(key: &[u8]) -> Self {
                // SAFETY: HMAC_CTX_init zero-initialises every byte of the ctx.
                let mut ctx = MaybeUninit::<aws::HMAC_CTX>::uninit();
                unsafe { aws::HMAC_CTX_init(ctx.as_mut_ptr()) };
                // SAFETY: HMAC_CTX_init completed, so ctx is initialised.
                let mut s = Self {
                    ctx: unsafe { ctx.assume_init() },
                };
                // SAFETY: ctx is initialised; key is a readable slice (possibly
                // empty); `$evp_md()` returns a static EVP_MD; engine is null.
                let rc = unsafe {
                    aws::HMAC_Init_ex(
                        &mut s.ctx,
                        key.as_ptr().cast::<std::ffi::c_void>(),
                        key.len(),
                        $evp_md(),
                        std::ptr::null_mut(),
                    )
                };
                assert_eq!(
                    rc, 1,
                    concat!(stringify!($Name), "::new HMAC_Init_ex failed")
                );
                s
            }

            pub fn update(&mut self, data: &[u8]) {
                if data.is_empty() {
                    return;
                }
                // SAFETY: ctx is initialised; data is a readable slice.
                let rc = unsafe { aws::HMAC_Update(&mut self.ctx, data.as_ptr(), data.len()) };
                assert_eq!(rc, 1, concat!(stringify!($Name), "::update failed"));
            }

            pub fn finish(mut self) -> [u8; $output_len] {
                let mut out = [0u8; $output_len];
                let mut out_len: u32 = 0;
                // SAFETY: ctx is initialised; out is exactly the MAC size.
                let rc = unsafe { aws::HMAC_Final(&mut self.ctx, out.as_mut_ptr(), &mut out_len) };
                assert_eq!(rc, 1, concat!(stringify!($Name), "::finish failed"));
                debug_assert_eq!(out_len as usize, $output_len);
                out
            }

            /// One-shot HMAC: a single FFI call, no context setup overhead.
            pub fn oneshot(key: &[u8], data: &[u8]) -> [u8; $output_len] {
                let mut out = [0u8; $output_len];
                let mut out_len: u32 = 0;
                // SAFETY: all slices are valid; out is exactly the MAC size.
                let p = unsafe {
                    aws::HMAC(
                        $evp_md(),
                        key.as_ptr().cast::<std::ffi::c_void>(),
                        key.len(),
                        data.as_ptr(),
                        data.len(),
                        out.as_mut_ptr(),
                        &mut out_len,
                    )
                };
                assert!(!p.is_null(), concat!(stringify!($Name), "::oneshot failed"));
                debug_assert_eq!(out_len as usize, $output_len);
                out
            }
        }
    };
}

impl_hmac!(HmacSha1, aws::EVP_sha1, SHA1_OUTPUT_LEN);
impl_hmac!(HmacSha256, aws::EVP_sha256, SHA256_OUTPUT_LEN);
impl_hmac!(HmacSha384, aws::EVP_sha384, SHA384_OUTPUT_LEN);

/// IKEv2-style PRF+ ([RFC 4306] §2.13) using HMAC-SHA1, used by SSTP
/// Crypto Binding CMK derivation ([MS-SSTP] §3.2.5.2.2). The
/// per-iteration input is `T_{n-1} | seed | len_le | n`, where `len_le`
/// is the requested output length as an unsigned 16-bit little-endian
/// integer per the spec.
///
/// The CMK case only ever asks for 20 octets (one HMAC-SHA1 block), so
/// the implementation is hard-coded to a single iteration.
pub fn prf_plus_sha1_cmk(key: &[u8; 32], seed: &[u8]) -> [u8; SHA1_OUTPUT_LEN] {
    const _: () = assert!(SHA1_OUTPUT_LEN <= u16::MAX as usize);
    #[allow(clippy::cast_possible_truncation)]
    let len_le = (SHA1_OUTPUT_LEN as u16).to_le_bytes();
    let mut h = HmacSha1::new(key);
    h.update(seed);
    h.update(&len_le);
    h.update(&[0x01]);
    h.finish()
}

/// PRF+ using HMAC-SHA256 ([MS-SSTP] §3.2.5.2.4). CMK output length is
/// 32 octets, which fits in one HMAC-SHA256 block.
pub fn prf_plus_sha256_cmk(key: &[u8; 32], seed: &[u8]) -> [u8; SHA256_OUTPUT_LEN] {
    const _: () = assert!(SHA256_OUTPUT_LEN <= u16::MAX as usize);
    #[allow(clippy::cast_possible_truncation)]
    let len_le = (SHA256_OUTPUT_LEN as u16).to_le_bytes();
    let mut h = HmacSha256::new(key);
    h.update(seed);
    h.update(&len_le);
    h.update(&[0x01]);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 2202 test case 1 (HMAC-SHA1).
    #[test]
    fn hmac_sha1_rfc2202_case1() {
        let key = [0x0bu8; 20];
        let out = HmacSha1::oneshot(&key, b"Hi There");
        let expected: [u8; 20] = [
            0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37,
            0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00,
        ];
        assert_eq!(out, expected);
    }

    // RFC 4231 test case 1 (HMAC-SHA256).
    #[test]
    fn hmac_sha256_rfc4231_case1() {
        let key = [0x0bu8; 20];
        let out = HmacSha256::oneshot(&key, b"Hi There");
        let expected: [u8; 32] = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(out, expected);
    }
}
