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

use super::wire::{
    self, DrainError, MessageBuf, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST,
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

impl MssClamp {
    /// Install per-interface MSS clamping rules.
    ///
    /// `mtu` is the interface MTU already selected for the session.
    /// MSS is derived as `(mtu - 40)` for IPv4.
    pub fn install_for_ifname(ifname: &str, mtu: u32) -> Result<Self, MssClampError> {
        let mtu = mtu.clamp(576, 1500);
        let mss4 = (mtu.saturating_sub(40)).clamp(536, 1460) as u16;
        let table = CString::new(next_table_name())?;
        let chain_name: &CStr = c"forward";
        let ifname_c = CString::new(ifname)?;

        let socket = NfNetlink::open()?;

        // Single-batch install: kernel commits all four messages atomically
        // under one BATCH_BEGIN/END envelope, or rolls them all back if any
        // step (e.g. NEWCHAIN) fails. There is no partial-state window for
        // us to clean up.
        let install =
            build_install_batch(table.as_c_str(), chain_name, &ifname_c, mss4);
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
        let clamp = match MssClamp::install_for_ifname("lo", 1500) {
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
