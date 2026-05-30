//! Per-session TCP MSS clamping via direct nf_tables netlink (IPv4).
//!
//! This installs a per-session table + FORWARD base chain and two
//! interface-scoped rules (iif/oif) using libnftnl through the Rust
//! `nftnl` crate. Dropping the guard deletes the whole table.

use std::ffi::{CStr, CString};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

use nftnl::expr::{Bitwise, Cmp, CmpOp, Expression, Immediate, InterfaceName, Meta, Register};
use nftnl::nftnl_sys;
use nftnl::{
    Batch, Chain, ChainType, FinalizedBatch, Hook, MsgType, Policy, ProtoFamily, Rule, Table,
};

#[derive(Debug, thiserror::Error)]
pub enum MssClampError {
    #[error("invalid table or interface name: {0}")]
    InvalidName(#[from] std::ffi::NulError),
    #[error("netlink send/ack failed during {op}: {source}")]
    Netlink {
        op: &'static str,
        #[source]
        source: std::io::Error,
    },
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
        let mss_be = mss4.to_be();
        let table = CString::new(next_table_name())?;
        let chain_name: &CStr = c"forward";
        let ifname_c = CString::new(ifname)?;

        let mut batch = Batch::new();
        let table_obj = Table::new(table.as_c_str(), ProtoFamily::Ipv4);
        batch.add(&table_obj, MsgType::Add);

        let mut chain = Chain::new(chain_name, &table_obj);
        chain.set_hook(Hook::Forward, -150);
        chain.set_type(ChainType::Filter);
        chain.set_policy(Policy::Accept);
        batch.add(&chain, MsgType::Add);

        let mut ingress = Rule::new(&chain);
        add_mss_set_exprs(&mut ingress, &ifname_c, true, mss_be);
        batch.add(&ingress, MsgType::Add);

        let mut egress = Rule::new(&chain);
        add_mss_set_exprs(&mut egress, &ifname_c, false, mss_be);
        batch.add(&egress, MsgType::Add);

        send_and_process("install", &batch.finalize())?;

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
        let mut batch = Batch::new();
        let table = Table::new(self.table.as_c_str(), ProtoFamily::Ipv4);
        batch.add(&table, MsgType::Del);
        if let Err(e) = send_and_process("delete-table", &batch.finalize()) {
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

fn send_and_process(op: &'static str, batch: &FinalizedBatch) -> Result<(), MssClampError> {
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)
        .map_err(|source| MssClampError::Netlink { op, source })?;
    let portid = socket.portid();
    socket
        .send_all(batch)
        .map_err(|source| MssClampError::Netlink { op, source })?;

    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let mut expected = batch.sequence_numbers();
    while !expected.is_empty() {
        for msg in socket
            .recv(&mut buffer)
            .map_err(|source| MssClampError::Netlink { op, source })?
        {
            let msg = msg.map_err(|source| MssClampError::Netlink { op, source })?;
            let Some(seq) = expected.next() else {
                return Ok(());
            };
            mnl::cb_run(msg, seq, portid)
                .map_err(|source| MssClampError::Netlink { op, source })?;
        }
    }
    Ok(())
}

fn add_mss_set_exprs(rule: &mut Rule<'_>, ifname: &CString, ingress: bool, mss_be: u16) {
    // Match on iifname/oifname.
    rule.add_expr(&if ingress {
        Meta::IifName
    } else {
        Meta::OifName
    });
    let match_if = InterfaceName::Exact(ifname.clone());
    rule.add_expr(&Cmp::new(CmpOp::Eq, &match_if));

    // Restrict to TCP packets.
    rule.add_expr(&Meta::L4Proto);
    rule.add_expr(&Cmp::new(CmpOp::Eq, libc::IPPROTO_TCP as u8));

    // Match `(tcp.flags & (syn|rst)) == syn`.
    rule.add_expr(&nftnl::nft_expr!(payload_raw th 13, 1));
    rule.add_expr(&Bitwise::new(0x06u8, 0u8));
    rule.add_expr(&Cmp::new(CmpOp::Eq, 0x02u8));

    // Load the new MSS (network byte order) into register 1.
    rule.add_expr(&Immediate::new(mss_be, Register::Reg1));

    // Write MSS into TCP option kind=2 (MSS), offset=2, len=2.
    rule.add_expr(&TcpOptionSet {
        option: 2,
        offset: 2,
        len: 2,
    });
}

struct TcpOptionSet {
    option: u8,
    offset: u32,
    len: u32,
}

impl Expression for TcpOptionSet {
    fn to_expr(&self, _rule: &Rule) -> ptr::NonNull<nftnl_sys::nftnl_expr> {
        // SAFETY: libnftnl allocates and owns the expression object; we set only
        // documented exthdr attributes with fixed-size scalar payloads.
        let expr = unsafe { nftnl_sys::nftnl_expr_alloc(c"exthdr".as_ptr()) };
        let Some(expr) = ptr::NonNull::new(expr) else {
            std::process::abort();
        };
        // `NFT_EXTHDR_OP_TCPOPT` is enum value 1 in nf_tables.h.
        const EXTHDR_OP_TCPOPT: u32 = 1;
        unsafe {
            nftnl_sys::nftnl_expr_set_u32(
                expr.as_ptr(),
                nftnl_sys::NFTNL_EXPR_EXTHDR_OP as u16,
                EXTHDR_OP_TCPOPT,
            );
            nftnl_sys::nftnl_expr_set_u32(
                expr.as_ptr(),
                nftnl_sys::NFTNL_EXPR_EXTHDR_TYPE as u16,
                self.option as u32,
            );
            nftnl_sys::nftnl_expr_set_u32(
                expr.as_ptr(),
                nftnl_sys::NFTNL_EXPR_EXTHDR_OFFSET as u16,
                self.offset,
            );
            nftnl_sys::nftnl_expr_set_u32(
                expr.as_ptr(),
                nftnl_sys::NFTNL_EXPR_EXTHDR_LEN as u16,
                self.len,
            );
            nftnl_sys::nftnl_expr_set_u32(
                expr.as_ptr(),
                nftnl_sys::NFTNL_EXPR_EXTHDR_SREG as u16,
                Register::Reg1.to_raw(),
            );
        }
        expr
    }
}
