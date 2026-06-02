//! Linux kernel TLS (kTLS) socket installation.
//!
//! Splits TLS record encryption/decryption between userspace (the
//! handshake) and the kernel (the steady-state record layer). After
//! a successful TLS handshake, [`install_aes_gcm_128`] /
//! [`install_aes_gcm_256`] / [`install_chacha20_poly1305`] enable
//! the `tls` ULP on the TCP socket and upload the negotiated
//! traffic keys via `TLS_TX` / `TLS_RX` `setsockopt`s. From that
//! point on, `read(2)` / `write(2)` on the socket move plaintext
//! records and the kernel handles framing, sequence numbering, and
//! AEAD.
//!
//! Supported AEAD suites:
//! * AES-128-GCM (TLS 1.2 `ECDHE-*-AES128-GCM-SHA256` /
//!   `AES128-GCM-SHA256`, TLS 1.3 `TLS_AES_128_GCM_SHA256`);
//! * AES-256-GCM (TLS 1.2 `ECDHE-*-AES256-GCM-SHA384` /
//!   `AES256-GCM-SHA384`, TLS 1.3 `TLS_AES_256_GCM_SHA384`);
//! * ChaCha20-Poly1305 (TLS 1.2 `ECDHE-*-CHACHA20-POLY1305`,
//!   TLS 1.3 `TLS_CHACHA20_POLY1305_SHA256`).
//!
//! That covers every AEAD a Windows SSTP client in the field
//! offers. Linux kTLS additionally supports AES-CCM, SM4, and ARIA
//! suites, but no Windows / sstpc client negotiates them, so they
//! are deliberately omitted.
//!
//! Reference: `Documentation/networking/tls.rst`,
//! `include/uapi/linux/tls.h`.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

use crate::crypto::hmac::{HmacSha256, HmacSha384};

/// `SOL_TLS` — kernel TLS setsockopt level (`include/uapi/linux/tls.h`).
pub const SOL_TLS: libc::c_int = 282;
/// `TCP_ULP` — TCP-level setsockopt that selects an Upper Layer
/// Protocol. Passing `"tls"` flips this socket into kTLS mode.
pub const TCP_ULP: libc::c_int = 31;

pub const TLS_TX: libc::c_int = 1;
pub const TLS_RX: libc::c_int = 2;

pub const TLS_1_2_VERSION: u16 = 0x0303;
pub const TLS_1_3_VERSION: u16 = 0x0304;

pub const TLS_CIPHER_AES_GCM_128: u16 = 51;
pub const TLS_CIPHER_AES_GCM_256: u16 = 52;
pub const TLS_CIPHER_CHACHA20_POLY1305: u16 = 54;

/// AES-128-GCM IV size on the kernel UAPI (the explicit nonce / low
/// 8 bytes of the TLS 1.3 12-byte nonce).
pub const AES_GCM_128_IV_LEN: usize = 8;
/// AES-128-GCM key length.
pub const AES_GCM_128_KEY_LEN: usize = 16;
/// AES-128-GCM salt — implicit nonce (TLS 1.2) or high 4 bytes of
/// the static IV (TLS 1.3).
pub const AES_GCM_128_SALT_LEN: usize = 4;
/// TLS record sequence number length on the wire.
pub const TLS_REC_SEQ_LEN: usize = 8;

/// AES-256-GCM key length.
pub const AES_GCM_256_KEY_LEN: usize = 32;
/// AES-256-GCM IV size on the kernel UAPI (same wire layout as the
/// 128-bit variant — only `key` changes width).
pub const AES_GCM_256_IV_LEN: usize = 8;
/// AES-256-GCM salt — implicit nonce (TLS 1.2) / high 4 bytes of
/// the static IV (TLS 1.3).
pub const AES_GCM_256_SALT_LEN: usize = 4;

/// ChaCha20-Poly1305 key length (RFC 7539 §2.5: a single 256-bit
/// key).
pub const CHACHA20_POLY1305_KEY_LEN: usize = 32;
/// ChaCha20-Poly1305 nonce length on the kernel UAPI. Unlike
/// AES-GCM the entire 96-bit nonce lives in the `iv` field; the
/// salt slot is empty (RFC 7905 derives the nonce as
/// `padded_seq XOR write_iv`, no implicit-nonce/explicit-nonce
/// split).
pub const CHACHA20_POLY1305_IV_LEN: usize = 12;
/// ChaCha20-Poly1305 has no salt — the entire nonce is in `iv`.
pub const CHACHA20_POLY1305_SALT_LEN: usize = 0;

/// Mirrors `struct tls_crypto_info` from `<linux/tls.h>`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TlsCryptoInfo {
    pub version: u16,
    pub cipher_type: u16,
}

/// Mirrors `struct tls12_crypto_info_aes_gcm_128` from `<linux/tls.h>`.
/// The kernel uses the same struct for both TLS 1.2 and 1.3
/// AES-128-GCM; only `info.version` and the IV/salt interpretation
/// differ.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TlsCryptoInfoAesGcm128 {
    pub info: TlsCryptoInfo,
    pub iv: [u8; AES_GCM_128_IV_LEN],
    pub key: [u8; AES_GCM_128_KEY_LEN],
    pub salt: [u8; AES_GCM_128_SALT_LEN],
    pub rec_seq: [u8; TLS_REC_SEQ_LEN],
}

/// Mirrors `struct tls12_crypto_info_aes_gcm_256` from `<linux/tls.h>`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TlsCryptoInfoAesGcm256 {
    pub info: TlsCryptoInfo,
    pub iv: [u8; AES_GCM_256_IV_LEN],
    pub key: [u8; AES_GCM_256_KEY_LEN],
    pub salt: [u8; AES_GCM_256_SALT_LEN],
    pub rec_seq: [u8; TLS_REC_SEQ_LEN],
}

/// Mirrors `struct tls12_crypto_info_chacha20_poly1305` from
/// `<linux/tls.h>`. Salt is zero-length: ChaCha20-Poly1305 (RFC 7905)
/// has no implicit-nonce split, so the full 12-byte static IV /
/// derived nonce lives in `iv`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TlsCryptoInfoChacha20Poly1305 {
    pub info: TlsCryptoInfo,
    pub iv: [u8; CHACHA20_POLY1305_IV_LEN],
    pub key: [u8; CHACHA20_POLY1305_KEY_LEN],
    pub salt: [u8; CHACHA20_POLY1305_SALT_LEN],
    pub rec_seq: [u8; TLS_REC_SEQ_LEN],
}

/// Install the `tls` ULP and the TX+RX AES-128-GCM crypto state on
/// `fd`. The two crypto-info blocks describe the server's outbound
/// (TX) and inbound (RX) traffic keys, salts (implicit nonces /
/// static-IV high bits), and starting record sequence numbers.
///
/// After this returns `Ok(())` the socket is fully kTLS-equipped:
/// `read(2)` returns plaintext, `write(2)` accepts plaintext. The
/// SSTP kmod's `SSTP_IOC_ATTACH` will then accept the fd.
pub fn install_aes_gcm_128(
    fd: BorrowedFd<'_>,
    tx: TlsCryptoInfoAesGcm128,
    rx: TlsCryptoInfoAesGcm128,
) -> io::Result<()> {
    set_ulp_tls(fd)?;
    set_crypto_info(fd, TLS_TX, &tx)?;
    set_crypto_info(fd, TLS_RX, &rx)?;
    Ok(())
}

/// Install the `tls` ULP and the TX+RX AES-256-GCM crypto state on
/// `fd`. See [`install_aes_gcm_128`] for semantics; this is the
/// 32-byte-key sibling for `*_AES256_GCM_SHA384` suites.
pub fn install_aes_gcm_256(
    fd: BorrowedFd<'_>,
    tx: TlsCryptoInfoAesGcm256,
    rx: TlsCryptoInfoAesGcm256,
) -> io::Result<()> {
    set_ulp_tls(fd)?;
    set_crypto_info(fd, TLS_TX, &tx)?;
    set_crypto_info(fd, TLS_RX, &rx)?;
    Ok(())
}

/// Install the `tls` ULP and the TX+RX ChaCha20-Poly1305 crypto
/// state on `fd`. See [`install_aes_gcm_128`] for semantics.
/// Requires Linux 5.11+ for kernel-side ChaCha20-Poly1305 kTLS
/// support; older kernels return `ENOENT` from the `crypto_info`
/// `setsockopt` and the caller falls back to the userspace data
/// path.
pub fn install_chacha20_poly1305(
    fd: BorrowedFd<'_>,
    tx: TlsCryptoInfoChacha20Poly1305,
    rx: TlsCryptoInfoChacha20Poly1305,
) -> io::Result<()> {
    set_ulp_tls(fd)?;
    set_crypto_info(fd, TLS_TX, &tx)?;
    set_crypto_info(fd, TLS_RX, &rx)?;
    Ok(())
}

fn set_ulp_tls(fd: BorrowedFd<'_>) -> io::Result<()> {
    // `"tls"` literal, not NUL-terminated — `setsockopt` takes an
    // explicit length and the kernel matches on prefix.
    let name = b"tls";
    // SAFETY: `fd` is a valid open socket. `name` is a 3-byte
    // readable buffer; we pass its length explicitly.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_TCP,
            TCP_ULP,
            name.as_ptr().cast(),
            libc::socklen_t::try_from(name.len()).expect("\"tls\" fits in socklen_t"),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_crypto_info<T>(fd: BorrowedFd<'_>, direction: libc::c_int, info: &T) -> io::Result<()> {
    let len = std::mem::size_of::<T>();
    // SAFETY: `fd` is a valid open socket already in `tls` ULP mode.
    // `info` points to a fully-initialised `#[repr(C)]` struct of
    // exactly `len` bytes; the kernel copies it in and stores it
    // internally.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            SOL_TLS,
            direction,
            std::ptr::from_ref::<T>(info).cast(),
            libc::socklen_t::try_from(len).expect("crypto_info fits in socklen_t"),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1) specialised to
/// SHA-256. Returns at most 32 bytes (one HMAC block); the kTLS
/// caller only needs 16 (key) or 12 (iv) per direction so a single
/// block always suffices.
///
/// ```text
/// HkdfLabel = struct {
///     uint16 length        = Length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;   // empty here
/// }
/// HKDF-Expand-Label(Secret, Label, Context="", Length)
///   = HKDF-Expand(Secret, HkdfLabel, Length)
/// ```
pub fn hkdf_expand_label_sha256(secret: &[u8], label: &str, length: usize) -> Vec<u8> {
    assert!(
        length <= 32,
        "hkdf_expand_label_sha256: length > 32 needs multi-block HKDF"
    );
    let full_label = {
        let mut s = String::with_capacity(6 + label.len());
        s.push_str("tls13 ");
        s.push_str(label);
        s
    };
    assert!(full_label.len() <= 255, "label too long");

    // Construct HkdfLabel.
    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1);
    let len_be = u16::try_from(length).expect("length <= 32").to_be_bytes();
    info.extend_from_slice(&len_be);
    info.push(u8::try_from(full_label.len()).expect("label len <= 255"));
    info.extend_from_slice(full_label.as_bytes());
    info.push(0); // empty context

    // T(1) = HMAC(secret, info || 0x01). Truncate to `length`.
    let mut h = HmacSha256::new(secret);
    h.update(&info);
    h.update(&[0x01]);
    let t1 = h.finish();
    t1[..length].to_vec()
}

/// SHA-384 sibling of [`hkdf_expand_label_sha256`], used by the
/// TLS 1.3 `TLS_AES_256_GCM_SHA384` ciphersuite. Produces at most
/// 48 bytes (one HMAC-SHA384 block).
pub fn hkdf_expand_label_sha384(secret: &[u8], label: &str, length: usize) -> Vec<u8> {
    assert!(
        length <= 48,
        "hkdf_expand_label_sha384: length > 48 needs multi-block HKDF"
    );
    let full_label = {
        let mut s = String::with_capacity(6 + label.len());
        s.push_str("tls13 ");
        s.push_str(label);
        s
    };
    assert!(full_label.len() <= 255, "label too long");

    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1);
    let len_be = u16::try_from(length).expect("length <= 48").to_be_bytes();
    info.extend_from_slice(&len_be);
    info.push(u8::try_from(full_label.len()).expect("label len <= 255"));
    info.extend_from_slice(full_label.as_bytes());
    info.push(0);

    let mut h = HmacSha384::new(secret);
    h.update(&info);
    h.update(&[0x01]);
    let t1 = h.finish();
    t1[..length].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8448 §3 Resumed 0-RTT Handshake: `client_handshake_traffic_secret`
    /// derives `key` and `iv` via HKDF-Expand-Label. We don't have the
    /// full vector handy here, but verify the basic shape: SHA-256
    /// HMAC produces 32 bytes; truncation respects the requested
    /// length.
    #[test]
    fn hkdf_expand_label_truncates() {
        let secret = [0u8; 32];
        let key = hkdf_expand_label_sha256(&secret, "key", 16);
        assert_eq!(key.len(), 16);
        let iv = hkdf_expand_label_sha256(&secret, "iv", 12);
        assert_eq!(iv.len(), 12);
    }

    /// Known-answer check: HKDF-Expand-Label with an all-zero secret,
    /// label "key", and length 16 should produce a deterministic
    /// value. The expected bytes were computed independently with
    /// `python -c "import hashlib, hmac; ..."`.
    #[test]
    fn hkdf_expand_label_known_answer_key() {
        let secret = [0u8; 32];
        let key = hkdf_expand_label_sha256(&secret, "key", 16);
        // info = 00 10 | 09 | "tls13 key" | 00
        // hmac_sha256(secret, info || 0x01)[..16]
        let expected: [u8; 16] = [
            0xcb, 0xee, 0x75, 0x71, 0xc6, 0x11, 0x03, 0x9c, 0xa3, 0x27, 0xa2, 0xe8, 0x79, 0xdf,
            0xcd, 0x45,
        ];
        assert_eq!(&key[..], &expected[..]);
    }

    /// Confirm the layout of the kernel ABI struct matches the
    /// expected wire size — 40 bytes for AES-128-GCM (4 header +
    /// 8 iv + 16 key + 4 salt + 8 seq).
    #[test]
    fn aes_gcm_128_crypto_info_is_40_bytes() {
        assert_eq!(std::mem::size_of::<TlsCryptoInfoAesGcm128>(), 40);
    }

    /// 4 header + 8 iv + 32 key + 4 salt + 8 seq = 56 bytes.
    #[test]
    fn aes_gcm_256_crypto_info_is_56_bytes() {
        assert_eq!(std::mem::size_of::<TlsCryptoInfoAesGcm256>(), 56);
    }

    /// Same shape KAT as the SHA-256 variant: HKDF-Expand-Label
    /// with an all-zero secret should truncate to the requested
    /// length without panicking.
    #[test]
    fn hkdf_expand_label_sha384_truncates() {
        let secret = [0u8; 48];
        let key = hkdf_expand_label_sha384(&secret, "key", 32);
        assert_eq!(key.len(), 32);
        let iv = hkdf_expand_label_sha384(&secret, "iv", 12);
        assert_eq!(iv.len(), 12);
    }
}
