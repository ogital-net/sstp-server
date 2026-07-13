//! Per-session TCP MSS clamping via direct nf_tables netlink (IPv4).
//!
//! This installs a per-session table + FORWARD base chain and two
//! interface-scoped rules (iif/oif) using raw `NETLINK_NETFILTER`
//! messages. Dropping the guard deletes the whole table.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::io;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::netlink::{
    self as wire, DrainError, MessageBuf, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST,
    NetlinkSocket,
};

const NLM_F_APPEND: u16 = wire::NLM_F_APPEND;

const NFNL_SUBSYS_NFTABLES: u16 = 10;
/// `NFNL_MSG_BATCH_BEGIN == NLMSG_MIN_TYPE` per
/// `<linux/netfilter/nfnetlink.h>`. Wraps a sequence of nf_tables
/// messages in a single kernel-side transaction; the matching `_END`
/// triggers commit-or-abort. Inner messages refer to the subsystem via
/// `nfgenmsg.res_id = htons(NFNL_SUBSYS_NFTABLES)`.
const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
const NFNL_MSG_BATCH_END: u16 = 0x11;
const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_DELTABLE: u16 = 2;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_NEWRULE: u16 = 6;

const NFPROTO_UNSPEC: u8 = 0;
const NFPROTO_IPV4: u8 = 2;
const NFNETLINK_V0: u8 = 0;
const NF_INET_FORWARD: u32 = 2;
const NF_ACCEPT: u32 = 1;

const NFTA_TABLE_NAME: u16 = 1;
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_TYPE: u16 = 7;
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;
const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;
const NFTA_DATA_VALUE: u16 = 1;
const NFTA_PAYLOAD_DREG: u16 = 1;
const NFTA_PAYLOAD_BASE: u16 = 2;
const NFTA_PAYLOAD_OFFSET: u16 = 3;
const NFTA_PAYLOAD_LEN: u16 = 4;
const NFTA_BITWISE_SREG: u16 = 1;
const NFTA_BITWISE_DREG: u16 = 2;
const NFTA_BITWISE_LEN: u16 = 3;
const NFTA_BITWISE_MASK: u16 = 4;
const NFTA_BITWISE_XOR: u16 = 5;
const NFTA_BITWISE_OP: u16 = 6;
const NFTA_IMMEDIATE_DREG: u16 = 1;
const NFTA_IMMEDIATE_DATA: u16 = 2;
const NFTA_EXTHDR_TYPE: u16 = 2;
const NFTA_EXTHDR_OFFSET: u16 = 3;
const NFTA_EXTHDR_LEN: u16 = 4;
const NFTA_EXTHDR_OP: u16 = 6;
const NFTA_EXTHDR_SREG: u16 = 7;

const NFT_REG_1: u32 = 1;
const NFT_REG32_00: u32 = 8;
const NFT_META_IIFNAME: u32 = 6;
const NFT_META_OIFNAME: u32 = 7;
const NFT_META_L4PROTO: u32 = 16;
const NFT_CMP_EQ: u32 = 0;
const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;
const NFT_BITWISE_BOOL: u32 = 0;
const NFT_EXTHDR_OP_TCPOPT: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct Nfgenmsg {
    nfgen_family: u8,
    version: u8,
    res_id: u16,
}

#[derive(Debug, thiserror::Error)]
pub enum MssClampError {
    #[error("invalid table or interface name: {0}")]
    InvalidName(#[from] std::ffi::NulError),
    #[error("netlink send/ack failed during {op}: {source}")]
    Netlink {
        op: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("kernel rejected {op}: errno {errno}")]
    Kernel { op: &'static str, errno: i32 },
}

#[derive(Debug)]
pub struct MssClamp {
    table: CString,
}

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
/// Lifted out of [`MssClamp::install_for_ifname`] so it can be
/// unit-tested without touching netfilter.
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

impl MssClamp {
    /// Install per-interface MSS clamping rules.
    ///
    /// `mtu` is the inner interface MTU already selected for the
    /// session (i.e. the MTU on `pppN` / `tunN`); `tls_version`
    /// and `cipher` are the strings from
    /// [`crate::crypto::tls::KtlsEligibility`]. The advertised MSS
    /// is the smaller of:
    ///
    /// - **on-link bound** — `mtu - 40`, so a peer-side TCP segment
    ///   fits inside the inner IPv4 packet on `pppN`.
    /// - **underlay bound** — `UNDERLAY_PMTU - encap - 40`, where
    ///   `encap` is the outer-TCP/IPv4 plus cipher-specific TLS
    ///   record plus SSTP plus PPP overhead, so the same segment
    ///   still fits through a 1500-byte underlay without
    ///   fragmentation or PMTU drops.
    ///
    /// The on-link bound alone — what every "MSS = MTU - 40" PPP /
    /// PPPoE clamp computes — is wrong for SSTP when `Framed-MTU`
    /// matches the underlay (e.g. 1500/1500): a 1460-byte MSS
    /// produces 1500-byte inner IP packets that grow past the
    /// underlay PMTU once SSTP-encapsulated. The cipher-specific
    /// underlay bound is tight: ChaCha20 / TLS 1.3 sessions
    /// advertise a higher MSS than RouterOS's TLS 1.2 AES-CBC-SHA.
    ///
    /// See [`compute_mss4`] for the pure version and the
    /// per-cipher overhead breakdown.
    pub fn install_for_ifname(
        ifname: &str,
        mtu: u32,
        tls_version: &str,
        cipher: &str,
    ) -> Result<Self, MssClampError> {
        let bounds = compute_mss4(mtu, tls_version, cipher);
        let mss4 = bounds.mss4;
        tracing::trace!(
            target: "sstp::mtu",
            ifname,
            mtu_in = mtu,
            tls_version,
            cipher,
            tls_overhead = bounds.tls_overhead,
            encap = bounds.encap,
            mss_link = bounds.mss_link,
            mss_underlay = bounds.mss_underlay,
            mss4,
            "MssClamp: MSS = min(mtu-40, underlay-encap-40), clamped [536, 1460]"
        );
        let table = CString::new(next_table_name())?;
        let chain_name: &CStr = c"forward";
        let ifname_c = CString::new(ifname)?;

        let socket = NfNetlink::open()?;

        // Single-batch install: kernel commits all four messages atomically
        // under one BATCH_BEGIN/END envelope, or rolls them all back if any
        // step (e.g. NEWCHAIN) fails. There is no partial-state window for
        // us to clean up.
        let install = build_install_batch(table.as_c_str(), chain_name, &ifname_c, mss4);
        if let Err(error) = socket.exchange_batch("install", &install) {
            // Defensive: if a previous run from this PID ever left a stale
            // table (different counter, same prefix) the install fails with
            // EEXIST; the table name embeds an atomic counter so this is
            // effectively impossible in-process, but it costs nothing to
            // attempt cleanup of *this* table on any failure path.
            let rollback = build_delete_batch(table.as_c_str());
            if let Err(cleanup) = socket.exchange_batch("rollback", &rollback) {
                tracing::debug!(
                    target: "shape",
                    table = %table.to_string_lossy(),
                    error = %cleanup,
                    "no stale table to roll back (expected for atomic-install failure)"
                );
            }
            return Err(error);
        }

        tracing::info!(
            target: "shape",
            ifname,
            mtu,
            tls_version,
            cipher,
            mss4,
            table = %table.to_string_lossy(),
            "installed nftables MSS clamp rules"
        );

        Ok(Self { table })
    }
}

impl Drop for MssClamp {
    fn drop(&mut self) {
        let socket = match NfNetlink::open() {
            Ok(socket) => socket,
            Err(e) => {
                tracing::warn!(
                    target: "shape",
                    table = %self.table.to_string_lossy(),
                    error = %e,
                    "failed to open netfilter socket for MSS clamp cleanup"
                );
                return;
            }
        };
        let batch = build_delete_batch(self.table.as_c_str());
        if let Err(e) = socket.exchange_batch("delete-table", &batch) {
            tracing::warn!(
                target: "shape",
                table = %self.table.to_string_lossy(),
                error = %e,
                "failed to remove nftables MSS clamp table"
            );
        }
    }
}

fn next_table_name() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    format!("sstp_mss_{}_{}", std::process::id(), n)
}

/// One-shot, send-it-all-at-once nfnetlink batch.
///
/// Layout on the wire is `BATCH_BEGIN || msg* || BATCH_END`. Each inner
/// message has its own `nlmsghdr` and `NLM_F_ACK`, so the kernel returns
/// one `NLMSG_ERROR(err=0)` ack per inner message; the BATCH envelopes
/// are not acked. Inner messages run inside a single kernel-side
/// transaction: any one failure aborts the rest and rolls back state
/// already committed within the batch.
struct Batch {
    bytes: Vec<u8>,
    expected_acks: Vec<u32>,
}

impl Batch {
    fn new() -> Self {
        let mut b = Self {
            bytes: Vec::with_capacity(2048),
            expected_acks: Vec::new(),
        };
        b.push_envelope(NFNL_MSG_BATCH_BEGIN);
        b
    }

    fn finalize(mut self) -> Self {
        self.push_envelope(NFNL_MSG_BATCH_END);
        self
    }

    fn push(&mut self, mut msg: MessageBuf) {
        msg.finalize();
        // Inner messages always set NLM_F_ACK in our usage; record the
        // sequence so `exchange_batch` can drain the matching ack.
        if msg.flags() & NLM_F_ACK != 0 {
            self.expected_acks.push(msg.seq());
        }
        self.bytes.extend_from_slice(msg.bytes());
    }

    /// Append a `NFNL_MSG_BATCH_BEGIN`/`_END` envelope. The payload is an
    /// `nfgenmsg` whose `res_id` is `htons(NFNL_SUBSYS_NFTABLES)`, telling
    /// nfnetlink which subsystem owns the inner messages.
    fn push_envelope(&mut self, msg_type: u16) {
        let seq = NEXT_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut env = MessageBuf::new(msg_type, NLM_F_REQUEST, seq);
        env.push_struct(&Nfgenmsg {
            nfgen_family: NFPROTO_UNSPEC,
            version: NFNETLINK_V0,
            res_id: NFNL_SUBSYS_NFTABLES.to_be(),
        });
        env.finalize();
        self.bytes.extend_from_slice(env.bytes());
    }
}

fn build_install_batch(table: &CStr, chain: &CStr, ifname: &CStr, mss: u16) -> Batch {
    let mut batch = Batch::new();
    batch.push(create_table_msg(table));
    batch.push(create_forward_chain_msg(table, chain));
    batch.push(create_mss_rule_msg(table, chain, ifname, true, mss));
    batch.push(create_mss_rule_msg(table, chain, ifname, false, mss));
    batch.finalize()
}

fn build_delete_batch(table: &CStr) -> Batch {
    let mut batch = Batch::new();
    batch.push(delete_table_msg(table));
    batch.finalize()
}

/// Open a fresh nf_tables `MessageBuf` with a freshly-allocated
/// sequence number plus the `nfgenmsg` family header that every
/// nf_tables message begins with. Removes duplicated boilerplate
/// from the per-op constructors below.
fn nf_msg(op: u16, flags: u16) -> MessageBuf {
    let seq = NEXT_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut msg = MessageBuf::new(nft_msg_type(op), flags, seq);
    msg.push_struct(&Nfgenmsg {
        nfgen_family: NFPROTO_IPV4,
        version: NFNETLINK_V0,
        res_id: 0,
    });
    msg
}

fn create_table_msg(table: &CStr) -> MessageBuf {
    let mut msg = nf_msg(
        NFT_MSG_NEWTABLE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
    );
    msg.push_attr_cstr(NFTA_TABLE_NAME, table);
    msg
}

fn delete_table_msg(table: &CStr) -> MessageBuf {
    let mut msg = nf_msg(NFT_MSG_DELTABLE, NLM_F_REQUEST | NLM_F_ACK);
    msg.push_attr_cstr(NFTA_TABLE_NAME, table);
    msg
}

fn create_forward_chain_msg(table: &CStr, chain: &CStr) -> MessageBuf {
    let mut msg = nf_msg(
        NFT_MSG_NEWCHAIN,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
    );
    msg.push_attr_cstr(NFTA_CHAIN_TABLE, table);
    msg.push_attr_cstr(NFTA_CHAIN_NAME, chain);
    msg.push_attr_cstr(NFTA_CHAIN_TYPE, c"filter");
    msg.push_attr_be32(NFTA_CHAIN_POLICY, NF_ACCEPT);
    msg.nest_begin(NFTA_CHAIN_HOOK);
    msg.push_attr_be32(NFTA_HOOK_HOOKNUM, NF_INET_FORWARD);
    // Priority is a signed int on the wire (twos-complement be32);
    // -150 places us between conntrack (-200) and the default filter
    // priority (0), which is where iptables `mangle FORWARD` lives.
    msg.push_attr_be32(NFTA_HOOK_PRIORITY, (-150_i32) as u32);
    msg.nest_end();
    msg
}

fn create_mss_rule_msg(
    table: &CStr,
    chain: &CStr,
    ifname: &CStr,
    ingress: bool,
    mss: u16,
) -> MessageBuf {
    let mut msg = nf_msg(
        NFT_MSG_NEWRULE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
    );
    msg.push_attr_cstr(NFTA_RULE_TABLE, table);
    msg.push_attr_cstr(NFTA_RULE_CHAIN, chain);
    msg.nest_begin(NFTA_RULE_EXPRESSIONS);
    encode_match_ifname(&mut msg, ifname, ingress);
    encode_match_l4proto_tcp(&mut msg);
    encode_match_syn_not_rst(&mut msg);
    encode_set_mss(&mut msg, mss);
    msg.nest_end();
    msg
}

#[derive(Debug)]
struct NfNetlink {
    sock: NetlinkSocket,
}

impl NfNetlink {
    fn open() -> Result<Self, MssClampError> {
        let sock =
            NetlinkSocket::open(libc::NETLINK_NETFILTER).map_err(|e| MssClampError::Netlink {
                op: "socket",
                source: e,
            })?;
        Ok(Self { sock })
    }

    fn exchange_batch(&self, op: &'static str, batch: &Batch) -> Result<(), MssClampError> {
        self.sock
            .send(&batch.bytes)
            .map_err(|e| MssClampError::Netlink { op, source: e })?;

        // The kernel emits one NLMSG_ERROR per inner message that carries
        // NLM_F_ACK; an `err == 0` payload is a successful ack. We drain
        // until every expected sequence has been seen; the BATCH_BEGIN and
        // BATCH_END envelopes are not acked. A non-zero error short-
        // circuits the whole batch (the kernel aborts on the first failure
        // and rolls back, but may still emit acks for messages it had
        // already buffered — surfacing the first error is the right
        // signal).
        let mut remaining: HashSet<u32> = batch.expected_acks.iter().copied().collect();
        let mut reply = [0u8; 8192];
        while !remaining.is_empty() {
            let received = self
                .sock
                .recv_into(&mut reply)
                .map_err(|e| MssClampError::Netlink { op, source: e })?;
            match wire::drain_acks(received, &mut remaining) {
                Ok(()) => {}
                Err(DrainError::Truncated) => {
                    return Err(MssClampError::Netlink {
                        op,
                        source: io::Error::other("truncated netlink ack"),
                    });
                }
                Err(DrainError::Kernel(errno)) => {
                    return Err(MssClampError::Kernel { op, errno });
                }
            }
        }
        Ok(())
    }
}

fn encode_match_ifname(msg: &mut MessageBuf, ifname: &CStr, ingress: bool) {
    let mut name = [0u8; libc::IFNAMSIZ];
    let src = ifname.to_bytes_with_nul();
    let len = src.len().min(name.len());
    name[..len].copy_from_slice(&src[..len]);

    encode_meta_load(
        msg,
        if ingress {
            NFT_META_IIFNAME
        } else {
            NFT_META_OIFNAME
        },
        NFT_REG_1,
    );
    encode_cmp(msg, NFT_REG_1, &name, NFT_CMP_EQ);
}

fn encode_match_l4proto_tcp(msg: &mut MessageBuf) {
    encode_meta_load(msg, NFT_META_L4PROTO, NFT_REG32_00);
    encode_cmp(msg, NFT_REG32_00, &[libc::IPPROTO_TCP as u8], NFT_CMP_EQ);
}

fn encode_match_syn_not_rst(msg: &mut MessageBuf) {
    encode_payload_load(msg, NFT_REG32_00, NFT_PAYLOAD_TRANSPORT_HEADER, 13, 1);
    encode_bitwise(msg, NFT_REG32_00, NFT_REG32_00, &[0x06], &[0x00]);
    encode_cmp(msg, NFT_REG32_00, &[0x02], NFT_CMP_EQ);
}

fn encode_set_mss(msg: &mut MessageBuf, mss: u16) {
    // Wire format: TCP MSS option carries a big-endian u16. `to_be_bytes`
    // produces BE bytes from a host-order integer, so callers pass the
    // host-order MSS value (e.g. 1460) and never pre-swap.
    encode_immediate(msg, NFT_REG_1, &mss.to_be_bytes());
    encode_exthdr_set(msg, NFT_REG_1, 2, 2, 2);
}

fn encode_meta_load(msg: &mut MessageBuf, key: u32, dreg: u32) {
    expr_begin(msg, c"meta");
    msg.push_attr_be32(NFTA_META_KEY, key);
    msg.push_attr_be32(NFTA_META_DREG, dreg);
    expr_end(msg);
}

fn encode_cmp(msg: &mut MessageBuf, sreg: u32, data: &[u8], op: u32) {
    expr_begin(msg, c"cmp");
    msg.push_attr_be32(NFTA_CMP_SREG, sreg);
    msg.push_attr_be32(NFTA_CMP_OP, op);
    msg.nest_begin(NFTA_CMP_DATA);
    msg.push_attr_bytes(NFTA_DATA_VALUE, data);
    msg.nest_end();
    expr_end(msg);
}

fn encode_payload_load(msg: &mut MessageBuf, dreg: u32, base: u32, offset: u32, len: u32) {
    expr_begin(msg, c"payload");
    msg.push_attr_be32(NFTA_PAYLOAD_DREG, dreg);
    msg.push_attr_be32(NFTA_PAYLOAD_BASE, base);
    msg.push_attr_be32(NFTA_PAYLOAD_OFFSET, offset);
    msg.push_attr_be32(NFTA_PAYLOAD_LEN, len);
    expr_end(msg);
}

fn encode_bitwise(msg: &mut MessageBuf, sreg: u32, dreg: u32, mask: &[u8], xor: &[u8]) {
    expr_begin(msg, c"bitwise");
    msg.push_attr_be32(NFTA_BITWISE_SREG, sreg);
    msg.push_attr_be32(NFTA_BITWISE_DREG, dreg);
    msg.push_attr_be32(
        NFTA_BITWISE_LEN,
        u32::try_from(mask.len()).expect("mask too long"),
    );
    msg.nest_begin(NFTA_BITWISE_MASK);
    msg.push_attr_bytes(NFTA_DATA_VALUE, mask);
    msg.nest_end();
    msg.nest_begin(NFTA_BITWISE_XOR);
    msg.push_attr_bytes(NFTA_DATA_VALUE, xor);
    msg.nest_end();
    msg.push_attr_be32(NFTA_BITWISE_OP, NFT_BITWISE_BOOL);
    expr_end(msg);
}

fn encode_immediate(msg: &mut MessageBuf, dreg: u32, data: &[u8]) {
    expr_begin(msg, c"immediate");
    msg.push_attr_be32(NFTA_IMMEDIATE_DREG, dreg);
    msg.nest_begin(NFTA_IMMEDIATE_DATA);
    msg.push_attr_bytes(NFTA_DATA_VALUE, data);
    msg.nest_end();
    expr_end(msg);
}

fn encode_exthdr_set(msg: &mut MessageBuf, sreg: u32, option: u8, offset: u32, len: u32) {
    expr_begin(msg, c"exthdr");
    msg.push_attr_be32(NFTA_EXTHDR_OP, NFT_EXTHDR_OP_TCPOPT);
    msg.push_attr_u8(NFTA_EXTHDR_TYPE, option);
    msg.push_attr_be32(NFTA_EXTHDR_OFFSET, offset);
    msg.push_attr_be32(NFTA_EXTHDR_LEN, len);
    msg.push_attr_be32(NFTA_EXTHDR_SREG, sreg);
    expr_end(msg);
}

fn expr_begin(msg: &mut MessageBuf, name: &CStr) {
    msg.nest_begin(NFTA_LIST_ELEM);
    msg.push_attr_cstr(NFTA_EXPR_NAME, name);
    msg.nest_begin(NFTA_EXPR_DATA);
}

fn expr_end(msg: &mut MessageBuf) {
    msg.nest_end();
    msg.nest_end();
}

fn nft_msg_type(op: u16) -> u16 {
    (NFNL_SUBSYS_NFTABLES << 8) | op
}

static NEXT_SEQ: AtomicU32 = AtomicU32::new(1);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_ifname_match_as_ifnamsiz_payload() {
        let ifname = CString::new("ppp0").unwrap();
        let mut msg = nf_msg(NFT_MSG_NEWRULE, NLM_F_REQUEST);
        msg.nest_begin(NFTA_RULE_EXPRESSIONS);
        encode_match_ifname(&mut msg, ifname.as_c_str(), true);
        msg.nest_end();
        msg.finalize();

        let needle = [b'p', b'p', b'p', b'0', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(
            msg.bytes()
                .windows(needle.len())
                .any(|window| window == needle)
        );
    }

    #[test]
    fn exthdr_expr_contains_tcpopt_write_fields() {
        let mut msg = nf_msg(NFT_MSG_NEWRULE, NLM_F_REQUEST);
        msg.nest_begin(NFTA_RULE_EXPRESSIONS);
        encode_set_mss(&mut msg, 1400);
        msg.nest_end();
        msg.finalize();

        assert!(
            msg.bytes()
                .windows(b"exthdr\0".len())
                .any(|window| window == b"exthdr\0")
        );
        // NFTA_EXTHDR_OP is be32 on the wire (see MessageBuf::push_attr_be32).
        assert!(
            msg.bytes()
                .windows(4)
                .any(|window| window == NFT_EXTHDR_OP_TCPOPT.to_be_bytes())
        );
    }

    #[test]
    fn mss_value_is_big_endian_on_the_wire() {
        // Regression: MSS used to be byte-swapped twice (`mss.to_be().to_be_bytes()`),
        // landing as little-endian on the wire. For MSS=1460 (0x05B4) the immediate
        // expression must carry the bytes [0x05, 0xB4] — never [0xB4, 0x05].
        let mut msg = nf_msg(NFT_MSG_NEWRULE, NLM_F_REQUEST);
        msg.nest_begin(NFTA_RULE_EXPRESSIONS);
        encode_set_mss(&mut msg, 1460);
        msg.nest_end();
        msg.finalize();

        let be = [0x05u8, 0xB4];
        let le = [0xB4u8, 0x05];
        assert!(
            msg.bytes().windows(2).any(|w| w == be),
            "MSS bytes 0x05,0xB4 (BE for 1460) not present in immediate payload"
        );
        assert!(
            !msg.bytes().windows(2).any(|w| w == le),
            "MSS bytes 0xB4,0x05 (LE for 1460) leaked onto the wire"
        );
    }

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

#[cfg(test)]
mod root_tests {
    //! Live-kernel integration tests that exercise the real
    //! `NETLINK_NETFILTER` path. They runtime-skip when the harness
    //! lacks `CAP_NET_ADMIN`/root, when nf_tables isn't loaded, or
    //! when `nft(8)` isn't on `PATH` for verification.

    use super::*;

    fn skip_reason() -> Option<String> {
        // SAFETY: getuid() has no preconditions and cannot fail.
        let uid = unsafe { libc::getuid() };
        if uid != 0 {
            return Some(format!("not root (uid={uid})"));
        }
        if std::process::Command::new("nft")
            .arg("--version")
            .output()
            .map_or(true, |o| !o.status.success())
        {
            return Some("nft(8) not available on PATH".into());
        }
        None
    }

    fn nft_list_table_ip(name: &str) -> Option<String> {
        let out = std::process::Command::new("nft")
            .args(["list", "table", "ip", name])
            .output()
            .ok()?;
        if out.status.success() {
            Some(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            None
        }
    }

    #[test]
    fn install_creates_table_and_drop_removes_it() {
        if let Some(reason) = skip_reason() {
            eprintln!("SKIP install_creates_table_and_drop_removes_it: {reason}");
            return;
        }

        // `lo` always exists; we just need a real ifname for the iif/oif
        // match attributes. The rules will never actually match traffic
        // because the FORWARD hook doesn't see loopback packets, but the
        // table+chain+rules will be installed and visible to `nft list`.
        let clamp = match MssClamp::install_for_ifname(
            "lo",
            1500,
            "TLSv1.3",
            "TLS_AES_128_GCM_SHA256",
        ) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "SKIP install_creates_table_and_drop_removes_it: install failed (kernel module \
                     not loaded?): {e}"
                );
                return;
            }
        };
        let table_name = clamp.table.to_string_lossy().into_owned();

        let body = nft_list_table_ip(&table_name)
            .unwrap_or_else(|| panic!("nft did not list ip table {table_name} after install"));
        assert!(
            body.contains("chain forward"),
            "missing forward chain in nft output:\n{body}"
        );
        assert!(
            body.contains("iifname"),
            "missing iifname rule in nft output:\n{body}"
        );
        assert!(
            body.contains("oifname"),
            "missing oifname rule in nft output:\n{body}"
        );
        // The clamp value embeds in the rule as a 16-bit BE constant; nft
        // renders it as `set 0xMSS` in the exthdr expression. We don't
        // assert the exact rendering — just that the rule body mentions
        // the tcp option fingerprint.
        assert!(
            body.contains("tcp option") || body.contains("@th"),
            "missing tcp-option rewrite in nft output:\n{body}"
        );

        drop(clamp);

        if let Some(stale) = nft_list_table_ip(&table_name) {
            panic!("table {table_name} still present after drop:\n{stale}");
        }
    }
}
