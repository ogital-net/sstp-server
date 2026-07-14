//! IPv4 TCP MSS computation for the SSTP underlay.
//!
//! The actual MSS-clamp *installation* lives in
//! [`crate::shape::mss_shared`], which registers a single shared
//! nftables table with one chain + named set per distinct MSS value
//! (O(1) per-packet lookup regardless of session count). This module
//! is the wire-agnostic, netfilter-free half: given the inner MTU and
//! the negotiated TLS version + cipher, [`compute_mss4`] returns the
//! MSS to advertise on the inner netdev.
//!
//! Splitting the pure computation out keeps it unit-testable without
//! touching netlink, and lets the session driver pick the MSS group an
//! interface joins in [`crate::shape::mss_shared::SharedMssTable::add`].

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

/// Per-record TLS overhead for kTLS-eligible ciphers, in bytes.
///
/// Counts the outer TLS record envelope only — no headers from
/// TCP / IPv4 / SSTP / PPP. Each value is the *maximum* number
/// of bytes the cipher adds to a single TLS record, so a clamp
/// derived from this number never underbudgets the underlay.
///
/// References:
///
/// - TLS 1.3 (RFC 8446 §5.2): `TLSCiphertext` is a 5-byte header
///   plus plaintext plus 1-byte inner content-type plus 16-byte
///   AEAD tag. All TLS 1.3 ciphers we accept are AEAD with a
///   16-byte tag, so the overhead is constant at 22 bytes
///   regardless of AES-GCM vs. ChaCha20-Poly1305.
/// - TLS 1.2 AES-GCM (RFC 5288): 5-byte header + 8-byte explicit
///   nonce + 16-byte tag = 29 bytes.
/// - TLS 1.2 ChaCha20-Poly1305 (RFC 7905 §2): 5-byte header +
///   16-byte tag = 21 bytes. The full 12-byte nonce is derived
///   from the per-record sequence number — there is no explicit
///   nonce on the wire.
/// - TLS 1.2 AES-CBC-SHA (RFC 5246 §6.2.3.2): 5-byte header +
///   16-byte IV + 1..16 byte pad + 20-byte HMAC-SHA1 = up to 56
///   bytes worst case. We use the upper bound. AES-CBC-SHA384
///   would be larger, but Windows / sstpc / RouterOS clients do
///   not offer it for SSTP, so the 56-byte ceiling covers every
///   cipher we see in the field.
fn tls_record_overhead(version: &str, cipher: &str) -> u32 {
    match version {
        "TLSv1.3" => 22,
        "TLSv1.2" => {
            if cipher.contains("CHACHA20") {
                21
            } else if cipher.contains("GCM") {
                29
            } else {
                // CBC-SHA / unknown TLS 1.2 cipher → assume the
                // worst (CBC-SHA) so we never under-budget.
                56
            }
        }
        // Unknown TLS version (the operator wired up some non-
        // standard backend, or we're being called before the
        // handshake completes). Worst-case it.
        _ => 56,
    }
}

/// Pure compute of the IPv4 MSS to advertise on the inner netdev,
/// given the inner MTU and the negotiated TLS version + cipher.
///
/// Bounded below by 536 (the minimum IPv4 MSS per RFC 1122
/// §3.3.3) and above by 1460 (`mtu=1500 - 40`). The lower bound
/// in particular is what keeps a degenerate `mtu=576` session
/// from advertising MSS=536 *and* a tiny underlay budget — we
/// always honour at least RFC 1122.
///
/// The `mss4` field is what [`crate::shape::mss_shared`] clamps
/// SYN segments to; the remaining fields are kept for diagnostic
/// logging and unit-test assertions.
pub(crate) fn compute_mss4(mtu: u32, version: &str, cipher: &str) -> Mss4Bounds {
    /// Underlay path MTU we plan around. 1500 = standard
    /// Ethernet; jumbo / non-1500 underlays are handled by the
    /// operator setting `Framed-MTU` per-session, not by the
    /// clamp.
    const UNDERLAY_PMTU: u32 = 1500;
    /// Inner IPv4 (20) + inner TCP (20).
    const INNER_IP_TCP: u32 = 40;
    /// Outer IPv4 (20) + outer TCP (20).
    const OUTER_IP_TCP: u32 = 40;
    /// SSTP data header per [MS-SSTP] §2.2.3.
    const SSTP_DATA: u32 = 4;
    /// PPP Address/Control/Protocol uncompressed (we don't
    /// negotiate ACFC / PFC).
    const PPP_ACP: u32 = 4;

    let tls = tls_record_overhead(version, cipher);
    let mtu_clamped = mtu.clamp(576, 1500);
    // On-link bound: a peer-side TCP segment must fit inside
    // the inner IPv4 packet on `pppN`.
    let mss_link = mtu_clamped.saturating_sub(INNER_IP_TCP);
    // Underlay bound: the same segment, after every layer of
    // encapsulation, must fit through `UNDERLAY_PMTU`.
    let encap = OUTER_IP_TCP + tls + SSTP_DATA + PPP_ACP;
    let mss_underlay = UNDERLAY_PMTU.saturating_sub(encap + INNER_IP_TCP);
    let mss4 = mss_link.min(mss_underlay).clamp(536, 1460) as u16;
    Mss4Bounds {
        mss_link,
        mss_underlay,
        mss4,
        tls_overhead: tls,
        encap,
    }
}

/// Result of [`compute_mss4`]. The fields beyond `mss4` are kept
/// for diagnostic logging and unit-test assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Mss4Bounds {
    pub mss_link: u32,
    pub mss_underlay: u32,
    pub mss4: u16,
    pub tls_overhead: u32,
    pub encap: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------
    // compute_mss4 — locks in the cipher-aware MSS table.
    //
    // Numbers below are computed as
    //   mss_link     = mtu_clamped - 40
    //   mss_underlay = 1500 - 40 (outer) - tls - 4 (SSTP) - 4 (PPP) - 40 (inner)
    //                = 1412 - tls
    //   mss4         = min(mss_link, mss_underlay) clamped to [536, 1460]
    //
    // The exhaustive coverage of the cipher allow-list keeps a
    // future "let's tighten/loosen the overhead constants" patch
    // from silently shifting an advertised MSS in the field.
    // ---------------------------------------------------------

    #[test]
    fn tls13_overhead_is_22_for_every_aead() {
        // TLS 1.3 (RFC 8446 §5.2): 5 + 1 inner-content-type + 16 tag.
        for cipher in [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
        ] {
            let b = compute_mss4(1500, "TLSv1.3", cipher);
            assert_eq!(b.tls_overhead, 22, "cipher={cipher}");
            assert_eq!(b.mss_underlay, 1390, "cipher={cipher}");
            assert_eq!(b.mss4, 1390, "cipher={cipher}");
        }
    }

    #[test]
    fn tls12_aes_gcm_overhead_is_29() {
        // RFC 5288: 5 + 8 explicit nonce + 16 tag.
        for cipher in [
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "AES128-GCM-SHA256",
            "AES256-GCM-SHA384",
        ] {
            let b = compute_mss4(1500, "TLSv1.2", cipher);
            assert_eq!(b.tls_overhead, 29, "cipher={cipher}");
            assert_eq!(b.mss_underlay, 1383, "cipher={cipher}");
            assert_eq!(b.mss4, 1383, "cipher={cipher}");
        }
    }

    #[test]
    fn tls12_chacha20_overhead_is_21() {
        // RFC 7905 §2: no explicit nonce — 5 + 16 tag.
        for cipher in [
            "ECDHE-RSA-CHACHA20-POLY1305",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
        ] {
            let b = compute_mss4(1500, "TLSv1.2", cipher);
            assert_eq!(b.tls_overhead, 21, "cipher={cipher}");
            assert_eq!(b.mss_underlay, 1391, "cipher={cipher}");
            assert_eq!(b.mss4, 1391, "cipher={cipher}");
        }
    }

    #[test]
    fn tls12_cbc_sha_uses_56_byte_worst_case() {
        // RFC 5246 §6.2.3.2: 5 + 16 IV + ≤16 pad + 20 HMAC-SHA1.
        // RouterOS / Mikrotik clients negotiate this for SSTP.
        let b = compute_mss4(1500, "TLSv1.2", "ECDHE-RSA-AES256-SHA");
        assert_eq!(b.tls_overhead, 56);
        assert_eq!(b.mss_underlay, 1356);
        assert_eq!(b.mss4, 1356);
    }

    #[test]
    fn unknown_version_falls_back_to_worst_case() {
        // Defensive: an unrecognised TLS version means we have no
        // idea what the record overhead is; assume CBC-SHA so we
        // never under-budget.
        let b = compute_mss4(1500, "SSLv3", "doesnt-matter");
        assert_eq!(b.tls_overhead, 56);
        assert_eq!(b.mss4, 1356);
    }

    #[test]
    fn unknown_tls12_cipher_falls_back_to_worst_case() {
        // Conservative: a TLS 1.2 cipher we don't recognise (no
        // GCM / no CHACHA20 in the name) must be assumed CBC.
        let b = compute_mss4(1500, "TLSv1.2", "ECDHE-RSA-AES256-SHA");
        assert_eq!(b.tls_overhead, 56);
        assert_eq!(b.mss4, 1356);
    }

    #[test]
    fn small_mtu_picks_link_bound() {
        // mtu=1280 → mss_link=1240; underlay bound is still
        // 1390 / 1383 / 1356 depending on cipher, so the link
        // bound wins.
        let b = compute_mss4(1280, "TLSv1.3", "TLS_AES_128_GCM_SHA256");
        assert_eq!(b.mss_link, 1240);
        assert_eq!(b.mss_underlay, 1390);
        assert_eq!(b.mss4, 1240);
    }

    #[test]
    fn mtu_below_576_floors_at_536() {
        // mtu=400 is illegal (RFC 1122 §3.3.3 sets the IPv4 MSS
        // floor at 536). compute_mss4 clamps the input to 576
        // first, then applies the [536, 1460] result clamp, so
        // we never advertise less than 536.
        let b = compute_mss4(400, "TLSv1.3", "TLS_AES_128_GCM_SHA256");
        assert_eq!(b.mss_link, 536); // 576 - 40
        assert_eq!(b.mss4, 536);
    }

    #[test]
    fn mtu_above_1500_clamps_to_1500() {
        // Jumbo MTUs are not supported on the underlay we plan
        // around; the input is clamped to 1500 before computing
        // the link bound.
        let b = compute_mss4(9000, "TLSv1.3", "TLS_AES_128_GCM_SHA256");
        assert_eq!(b.mss_link, 1460); // 1500 - 40, not 8960
        assert_eq!(b.mss4, 1390); // underlay still wins
    }

    #[test]
    fn real_session_from_log_lands_at_1383() {
        // Captured from a live trace (2026-06-01) — TLS 1.2 +
        // AES256-GCM-SHA384, Framed-MTU honoured at 1500. The
        // pre-fix clamp emitted mss4=1356 (always-worst-case);
        // the cipher-aware version must emit 1383.
        let b = compute_mss4(1500, "TLSv1.2", "AES256-GCM-SHA384");
        assert_eq!(b.mss4, 1383);
    }

    #[test]
    fn encap_total_is_self_consistent() {
        // The struct's `encap` field must equal the sum of its
        // parts: outer(40) + tls + sstp(4) + ppp(4).
        for (version, cipher, expected_tls) in [
            ("TLSv1.3", "TLS_AES_128_GCM_SHA256", 22),
            ("TLSv1.2", "AES256-GCM-SHA384", 29),
            ("TLSv1.2", "ECDHE-RSA-CHACHA20-POLY1305", 21),
            ("TLSv1.2", "ECDHE-RSA-AES256-SHA", 56),
        ] {
            let b = compute_mss4(1500, version, cipher);
            assert_eq!(b.tls_overhead, expected_tls, "{version}/{cipher}");
            assert_eq!(b.encap, 40 + expected_tls + 4 + 4, "{version}/{cipher}");
        }
    }
}
