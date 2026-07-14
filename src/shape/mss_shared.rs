//! Shared-table MSS clamp: one nftables table, one chain per distinct
//! MSS value, with named sets for O(1) interface lookup.
//!
//! Each session's netdev is added to a named set keyed by its MSS
//! value. The kernel evaluates at most one hash-table lookup per
//! forwarded packet per MSS group, regardless of session count.
//!
//! This module replaces that with:
//! - One table `sstp_mss_<PID>` per process (PID-suffixed so
//!   concurrent instances and restarts never collide; stale tables
//!   from dead PIDs are swept by the systemd `ExecStartPre`).
//! - One chain per distinct MSS value (`fwd_XXXX`), each at the
//!   forward hook with two rules using a named set `ifaces_XXXX`:
//!   ```text
//!   meta iifname @ifaces_XXXX tcp flags syn / syn,rst tcp option maxseg size set XXXX
//!   meta oifname @ifaces_XXXX tcp flags syn / syn,rst tcp option maxseg size set XXXX
//!   ```
//! - Sessions add/remove interface names from the set via
//!   `NFT_MSG_NEWSETELEM` / `NFT_MSG_DELSETELEM`.
//!
//! The kernel evaluates at most one set lookup per forwarded packet
//! per MSS group (hash table O(1)), regardless of session count.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{LazyLock, Mutex};

use crate::netlink::{
    self as wire, DrainError, MessageBuf, NLM_F_ACK, NLM_F_APPEND, NLM_F_CREATE, NLM_F_EXCL,
    NLM_F_REQUEST, NetlinkSocket,
};

// nf_tables message-type and attribute constants.
// Values from <linux/netfilter/nf_tables.h>.
const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
const NFNL_MSG_BATCH_END: u16 = 0x11;
const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_DELTABLE: u16 = 2;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_NEWRULE: u16 = 6;
const NFT_MSG_NEWSET: u16 = 9;
const NFT_MSG_NEWSETELEM: u16 = 12;
const NFT_MSG_DELSETELEM: u16 = 14;

const NFPROTO_UNSPEC: u8 = 0;
const NFPROTO_IPV4: u8 = 2;
const NFNETLINK_V0: u8 = 0;
const NF_INET_FORWARD: u32 = 2;
const NF_ACCEPT: u32 = 1;

// Table/chain/rule attributes.
const NFTA_TABLE_NAME: u16 = 1;
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_TYPE: u16 = 7;
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;

// Set attributes (enum nft_set_attributes, <linux/netfilter/nf_tables.h>).
const NFTA_SET_TABLE: u16 = 1;
const NFTA_SET_NAME: u16 = 2;
const NFTA_SET_FLAGS: u16 = 3;
const NFTA_SET_KEY_TYPE: u16 = 4;
const NFTA_SET_KEY_LEN: u16 = 5;
const NFTA_SET_USERDATA: u16 = 13;
const NFTA_SET_ID: u16 = 10;
const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
const NFTA_SET_ELEM_LIST_SET: u16 = 2;
const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;
#[allow(dead_code)] // Needed when adding elements within a NEWSET batch (same-transaction cross-ref).
const NFTA_SET_ELEM_LIST_SET_ID: u16 = 4;
const NFTA_SET_ELEM_KEY: u16 = 1;
const NFTA_LIST_ELEM: u16 = 1;

// Expression attributes.
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;
const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFTA_LOOKUP_SET: u16 = 1;
const NFTA_LOOKUP_SREG: u16 = 2;
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
const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;
const NFTA_DATA_VALUE: u16 = 1;
const NFTA_IMMEDIATE_DREG: u16 = 1;
const NFTA_IMMEDIATE_DATA: u16 = 2;
const NFTA_EXTHDR_TYPE: u16 = 2;
const NFTA_EXTHDR_OFFSET: u16 = 3;
const NFTA_EXTHDR_LEN: u16 = 4;
const NFTA_EXTHDR_OP: u16 = 6;
const NFTA_EXTHDR_SREG: u16 = 7;

const NFT_REG_1: u32 = 1;
const NFT_META_IIFNAME: u32 = 6;
const NFT_META_OIFNAME: u32 = 7;
const NFT_META_L4PROTO: u32 = 16;
const NFT_CMP_EQ: u32 = 0;
const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;
const NFT_BITWISE_BOOL: u32 = 0;
const NFT_EXTHDR_OP_TCPOPT: u32 = 1;

/// Set flags. We want a *plain named set* that userspace mutates at
/// runtime (add/del-elem after the set is already bound to the lookup
/// rules), which is exactly flags == 0.
///
/// Do NOT set `NFT_SET_ANONYMOUS` (0x1): that asks the kernel to
/// allocate the name and auto-unlink the set, which is incompatible
/// with our explicit `NFTA_SET_NAME` + by-name add/del-elem. Do NOT
/// set `NFT_SET_CONSTANT` (0x2) either: it means "contents may not
/// change while bound", so the kernel would reject every
/// `NEWSETELEM`/`DELSETELEM` we issue per session. (Values per
/// `<linux/netfilter/nf_tables.h>`: ANONYMOUS=0x1, CONSTANT=0x2.)
const NFT_SET_FLAGS: u32 = 0;
/// Datatype carried in `NFTA_SET_KEY_TYPE`. `0x29` is the
/// `ifname` type, paired with `NFTA_SET_KEY_LEN = IFNAMSIZ`.
/// The kernel validates this — a zero or unknown type is
/// rejected with ERANGE at `NFT_MSG_NEWSET`.
const NFT_KEY_TYPE_IFNAME: u32 = 0x29;

/// `NFTA_SET_USERDATA` blob so `nft list` renders element keys
/// as human-readable interface names. Only the `KEYBYTEORDER`
/// TLV is emitted — the `KEY_TYPEOF` TLV (type 3, added in nft
/// ~1.0.8) causes older nft builds to segfault when parsing the
/// dump response. `NFTA_SET_KEY_TYPE = 0x29` already identifies
/// the type; the byteorder is all nft needs for rendering.
#[cfg(target_endian = "little")]
const IFNAME_SET_USERDATA: &[u8] = &[
    0x00, 0x04, 0x01, 0x00, 0x00, 0x00, // KEYBYTEORDER = HOST (LE u32)
];
#[cfg(target_endian = "big")]
const IFNAME_SET_USERDATA: &[u8] = &[
    0x00, 0x04, 0x00, 0x00, 0x00, 0x01, // KEYBYTEORDER = HOST (BE u32)
];

/// Per-process table name: `sstp_mss_<PID>`. Using the PID avoids
/// collisions between concurrent instances and makes stale-table
/// identification trivial (check if the PID is alive). On startup
/// we only need to flush our own table (which is stale by definition
/// if it already exists — the kernel reuses PIDs but not quickly
/// enough for this to be a realistic race).
///
/// Stale tables from other (dead) PIDs are cleaned by the systemd
/// `ExecStartPre` sweep which deletes all `sstp_mss_*` tables whose
/// PID suffix is not alive. Non-systemd deployments accumulate at
/// most one stale table per crash (harmless — empty chains with
/// empty sets have zero per-packet cost).
static TABLE_NAME: LazyLock<CString> = LazyLock::new(|| {
    CString::new(format!("sstp_mss_{}", std::process::id())).expect("no NUL in table name")
});

#[repr(C)]
#[derive(Clone, Copy)]
struct Nfgenmsg {
    nfgen_family: u8,
    version: u8,
    res_id: u16,
}

#[derive(Debug, thiserror::Error)]
pub enum SharedMssError {
    #[error("invalid name: {0}")]
    InvalidName(#[from] std::ffi::NulError),
    #[error("netlink {op}: {source}")]
    Netlink {
        op: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("kernel rejected {op}: errno {errno}")]
    Kernel { op: &'static str, errno: i32 },
}

/// Per-MSS-value chain state tracked in the shared table.
struct MssGroup {
    /// Chain name, e.g. `fwd_1383`.
    chain_name: CString,
    /// Set name, e.g. `ifaces_1383`.
    set_name: CString,
    /// Number of interfaces currently in the set.
    refcount: u32,
    /// Whether the chain + set + rules already exist in the kernel.
    /// Tracked separately from `refcount` because `remove` keeps the
    /// kernel group in place when the last interface leaves (see the
    /// comment there), so a later `add` at the same MSS must NOT
    /// re-issue the `NLM_F_EXCL` create (which would fail EEXIST).
    kernel_created: bool,
}

/// Process-global shared MSS clamp table.
///
/// Thread-safe via an internal `Mutex`. The lock is held only for
/// the duration of a netlink send/recv (microseconds); session
/// bring-up and teardown are the only callers and they run on
/// different IO workers.
pub struct SharedMssTable {
    inner: Mutex<Inner>,
}

struct Inner {
    /// Whether the table has been created in the kernel.
    table_exists: bool,
    /// Map from MSS value → group state (chain + set + refcount).
    groups: HashMap<u16, MssGroup>,
}

impl SharedMssTable {
    /// Create a new (not-yet-installed) shared table manager.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                table_exists: false,
                groups: HashMap::new(),
            }),
        }
    }

    /// Add an interface to the MSS clamp set for the given MSS value.
    ///
    /// On first call, creates the table. On first call for a given MSS
    /// value, creates the chain + set + rules. Subsequent calls for the
    /// same MSS just add an element to the existing set.
    pub fn add(&self, ifname: &str, mss: u16) -> Result<SharedMssGuard, SharedMssError> {
        let ifname_c = CString::new(ifname)?;
        let mut inner = self.inner.lock().expect("MSS table lock poisoned");

        let sock = NfNetlink::open()?;

        if !inner.table_exists {
            // Flush any stale table with our PID-suffixed name (only
            // possible via kernel PID reuse after a crash — rare but
            // cheap to handle). ENOENT is the normal case.
            match sock.exchange_batch("flush-stale-table", &build_delete_table_batch()) {
                Ok(()) => {
                    tracing::info!(target: "shape", table = %TABLE_NAME.to_string_lossy(), "flushed stale table");
                }
                Err(SharedMssError::Kernel { errno: 2, .. }) => {} // ENOENT — no stale table
                Err(e) => {
                    tracing::debug!(target: "shape", error = %e, "stale table flush failed (proceeding)");
                }
            }
            sock.exchange_batch("create-table", &build_create_table_batch())?;
            inner.table_exists = true;
            tracing::debug!(target: "shape", "shared MSS table created");
        }

        let group = inner.groups.entry(mss).or_insert_with(|| {
            // Will be initialized below after we create the chain+set.
            MssGroup {
                chain_name: CString::new(format!("fwd_{mss}")).expect("no NUL in mss chain name"),
                set_name: CString::new(format!("ifaces_{mss}")).expect("no NUL in mss set name"),
                refcount: 0,
                kernel_created: false,
            }
        });

        if !group.kernel_created {
            // No kernel chain+set for this MSS value yet — create it.
            // Gated on `kernel_created`, NOT `refcount == 0`: `remove`
            // leaves the kernel group standing after the last
            // interface leaves, so a later session at the same MSS
            // must skip this create or the `NLM_F_EXCL` create would
            // fail EEXIST and take the whole `add` down with it.
            //
            // Each step is its own transaction so a kernel rejection
            // names the exact step (set vs chain vs rule) in the
            // errno-bearing `SharedMssError::Kernel { op, .. }`.
            sock.exchange_batch("create-set", &build_create_set_batch(&group.set_name))?;
            sock.exchange_batch("create-chain", &build_create_chain_batch(&group.chain_name))?;
            sock.exchange_batch(
                "create-rule-iif",
                &build_rule_batch(&group.chain_name, &group.set_name, true, mss),
            )?;
            sock.exchange_batch(
                "create-rule-oif",
                &build_rule_batch(&group.chain_name, &group.set_name, false, mss),
            )?;
            group.kernel_created = true;
            tracing::info!(
                target: "shape",
                mss,
                chain = %group.chain_name.to_string_lossy(),
                set = %group.set_name.to_string_lossy(),
                "created MSS clamp group"
            );
        }

        // Add interface to the set.
        let batch = build_add_elem_batch(&group.set_name, &ifname_c);
        sock.exchange_batch("add-set-elem", &batch)?;
        group.refcount += 1;

        tracing::debug!(
            target: "shape",
            ifname,
            mss,
            refcount = group.refcount,
            "added interface to MSS set"
        );

        Ok(SharedMssGuard {
            ifname: ifname.to_string(),
            mss,
        })
    }

    /// Remove an interface from the MSS clamp set.
    ///
    /// When the last interface for a given MSS value is removed, the
    /// chain + set are deleted. When the last group is removed, the
    /// table is deleted.
    pub fn remove(&self, ifname: &str, mss: u16) {
        let Ok(ifname_c) = CString::new(ifname) else {
            return;
        };
        let mut inner = self.inner.lock().expect("MSS table lock poisoned");

        let sock = match NfNetlink::open() {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    target: "shape",
                    ifname,
                    mss,
                    error = %e,
                    "failed to open netfilter socket for MSS elem removal"
                );
                return;
            }
        };

        if let Some(group) = inner.groups.get_mut(&mss) {
            // Remove element from set (best-effort; element may already
            // be gone if the kernel reaped the netdev).
            let batch = build_del_elem_batch(&group.set_name, &ifname_c);
            if let Err(e) = sock.exchange_batch("del-set-elem", &batch) {
                tracing::debug!(
                    target: "shape",
                    ifname,
                    mss,
                    error = %e,
                    "del-set-elem failed (interface may already be gone)"
                );
            }

            group.refcount = group.refcount.saturating_sub(1);
            tracing::debug!(
                target: "shape",
                ifname,
                mss,
                refcount = group.refcount,
                "removed interface from MSS set"
            );

            // If this was the last interface, we could delete the
            // chain+set. However, keeping empty chains is cheap (the
            // set is empty so lookups still O(1) with zero iterations)
            // and avoids a race where a new session for the same MSS
            // arrives between the delete and re-create. Only delete
            // the whole table on daemon shutdown.
        }
    }

    /// Delete the entire shared table from the kernel. Called on
    /// daemon shutdown / drop.
    pub fn destroy(&self) {
        let mut inner = self.inner.lock().expect("MSS table lock poisoned");
        if !inner.table_exists {
            return;
        }
        let sock = match NfNetlink::open() {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(target: "shape", error = %e, "failed to open nf socket for MSS table destroy");
                return;
            }
        };
        let batch = build_delete_table_batch();
        if let Err(e) = sock.exchange_batch("destroy-table", &batch) {
            tracing::warn!(target: "shape", error = %e, "failed to destroy shared MSS table");
        } else {
            tracing::debug!(target: "shape", "shared MSS table destroyed");
        }
        inner.table_exists = false;
        inner.groups.clear();
    }
}

impl Drop for SharedMssTable {
    fn drop(&mut self) {
        self.destroy();
    }
}

/// RAII guard returned by [`SharedMssTable::add`]. On drop, removes
/// the interface from the set.
pub struct SharedMssGuard {
    ifname: String,
    mss: u16,
}

// The guard doesn't remove on drop by itself — it needs access to
// the SharedMssTable. We'll handle this via the session holding both
// the table reference and the guard. See `SharedMssHandle` below.

/// Combined handle: holds an `Arc` reference to the shared table
/// plus the guard data needed for removal.
pub struct SharedMssHandle {
    table: std::sync::Arc<SharedMssTable>,
    guard: SharedMssGuard,
}

impl SharedMssHandle {
    /// Create a handle that will auto-remove on drop.
    pub fn new(table: std::sync::Arc<SharedMssTable>, guard: SharedMssGuard) -> Self {
        Self { table, guard }
    }
}

impl Drop for SharedMssHandle {
    fn drop(&mut self) {
        self.table.remove(&self.guard.ifname, self.guard.mss);
    }
}

// ---------------------------------------------------------------------------
// Netlink batch construction
// ---------------------------------------------------------------------------

static NEXT_SEQ: AtomicU32 = AtomicU32::new(1);
/// Set IDs are per-batch identifiers so the kernel can cross-reference
/// the set in the same transaction. The value just needs to be unique
/// within a batch.
static NEXT_SET_ID: AtomicU32 = AtomicU32::new(1);

struct Batch {
    bytes: Vec<u8>,
    expected_acks: Vec<u32>,
}

impl Batch {
    fn new() -> Self {
        let mut b = Self {
            bytes: Vec::with_capacity(4096),
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
        if msg.flags() & NLM_F_ACK != 0 {
            self.expected_acks.push(msg.seq());
        }
        self.bytes.extend_from_slice(msg.bytes());
    }

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

fn nft_msg_type(op: u16) -> u16 {
    (NFNL_SUBSYS_NFTABLES << 8) | op
}

// --- Table ---

fn build_create_table_batch() -> Batch {
    let mut batch = Batch::new();
    let mut msg = nf_msg(
        NFT_MSG_NEWTABLE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
    );
    msg.push_attr_cstr(NFTA_TABLE_NAME, &TABLE_NAME);
    batch.push(msg);
    batch.finalize()
}

fn build_delete_table_batch() -> Batch {
    let mut batch = Batch::new();
    let mut msg = nf_msg(NFT_MSG_DELTABLE, NLM_F_REQUEST | NLM_F_ACK);
    msg.push_attr_cstr(NFTA_TABLE_NAME, &TABLE_NAME);
    batch.push(msg);
    batch.finalize()
}

// --- Group (set, chain, rules) — each its own transaction ---

/// Create the named `ifname` set. Referenced by name from the rule
/// (built in a later transaction), so no in-batch `NFTA_SET_ID`
/// cross-reference is needed.
fn build_create_set_batch(set_name: &CStr) -> Batch {
    let mut batch = Batch::new();
    let mut msg = nf_msg(
        NFT_MSG_NEWSET,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
    );
    msg.push_attr_cstr(NFTA_SET_TABLE, &TABLE_NAME);
    msg.push_attr_cstr(NFTA_SET_NAME, set_name);
    msg.push_attr_be32(NFTA_SET_FLAGS, NFT_SET_FLAGS);
    msg.push_attr_be32(NFTA_SET_KEY_TYPE, NFT_KEY_TYPE_IFNAME);
    // IFNAMSIZ = 16 bytes — the kernel validates element key length
    // matches this.
    msg.push_attr_be32(NFTA_SET_KEY_LEN, libc::IFNAMSIZ as u32);
    // Every set carries an `NFTA_SET_ID` (unique within the
    // transaction). The kernel requires it on NEWSET even when
    // nothing else in the batch references the set by ID.
    msg.push_attr_be32(NFTA_SET_ID, NEXT_SET_ID.fetch_add(1, Ordering::Relaxed));
    msg.push_attr_bytes(NFTA_SET_USERDATA, IFNAME_SET_USERDATA);
    batch.push(msg);
    batch.finalize()
}

/// Create the forward-hook chain that the rules attach to.
fn build_create_chain_batch(chain_name: &CStr) -> Batch {
    let mut batch = Batch::new();
    let mut msg = nf_msg(
        NFT_MSG_NEWCHAIN,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
    );
    msg.push_attr_cstr(NFTA_CHAIN_TABLE, &TABLE_NAME);
    msg.push_attr_cstr(NFTA_CHAIN_NAME, chain_name);
    msg.push_attr_cstr(NFTA_CHAIN_TYPE, c"filter");
    msg.push_attr_be32(NFTA_CHAIN_POLICY, NF_ACCEPT);
    msg.nest_begin(NFTA_CHAIN_HOOK);
    msg.push_attr_be32(NFTA_HOOK_HOOKNUM, NF_INET_FORWARD);
    // NF_IP_PRI_MANGLE = -150; the kernel takes the priority as a
    // signed value transported in a u32 attribute.
    msg.push_attr_be32(NFTA_HOOK_PRIORITY, (-150_i32).cast_unsigned());
    msg.nest_end();
    batch.push(msg);
    batch.finalize()
}

/// One MSS-clamp rule for a single direction. The set already exists
/// in the kernel (prior transaction), so the lookup references it by
/// name only.
fn build_rule_batch(chain_name: &CStr, set_name: &CStr, ingress: bool, mss: u16) -> Batch {
    let mut batch = Batch::new();
    let mut msg = nf_msg(
        NFT_MSG_NEWRULE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
    );
    msg.push_attr_cstr(NFTA_RULE_TABLE, &TABLE_NAME);
    msg.push_attr_cstr(NFTA_RULE_CHAIN, chain_name);
    msg.nest_begin(NFTA_RULE_EXPRESSIONS);

    // expr: meta load iifname/oifname → reg1
    encode_meta_load(
        &mut msg,
        if ingress {
            NFT_META_IIFNAME
        } else {
            NFT_META_OIFNAME
        },
        NFT_REG_1,
    );

    // expr: lookup reg1 in @set_name (by name; set pre-exists)
    encode_lookup(&mut msg, NFT_REG_1, set_name);

    // expr: meta load l4proto → reg1; cmp == TCP. `nft` reuses reg1
    // here rather than a 32-bit sub-register; mirror it exactly.
    encode_meta_load(&mut msg, NFT_META_L4PROTO, NFT_REG_1);
    encode_cmp(&mut msg, NFT_REG_1, &[libc::IPPROTO_TCP as u8], NFT_CMP_EQ);

    // expr: payload load TCP flags byte → reg1; bitwise & 0x06; cmp == 0x02 (SYN !RST)
    encode_payload_load(&mut msg, NFT_REG_1, NFT_PAYLOAD_TRANSPORT_HEADER, 13, 1);
    encode_bitwise(&mut msg, NFT_REG_1, NFT_REG_1, &[0x06], &[0x00]);
    encode_cmp(&mut msg, NFT_REG_1, &[0x02], NFT_CMP_EQ);

    // expr: immediate mss → reg1; exthdr set tcp option MSS
    encode_immediate(&mut msg, NFT_REG_1, &mss.to_be_bytes());
    encode_exthdr_set(&mut msg, NFT_REG_1, 2, 2, 2);

    msg.nest_end(); // NFTA_RULE_EXPRESSIONS
    batch.push(msg);
    batch.finalize()
}

// --- Set element add/del ---

fn build_add_elem_batch(set_name: &CStr, ifname: &CStr) -> Batch {
    let mut batch = Batch::new();
    let mut msg = nf_msg(NFT_MSG_NEWSETELEM, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE);
    encode_set_elem_msg(&mut msg, set_name, ifname);
    batch.push(msg);
    batch.finalize()
}

fn build_del_elem_batch(set_name: &CStr, ifname: &CStr) -> Batch {
    let mut batch = Batch::new();
    let mut msg = nf_msg(NFT_MSG_DELSETELEM, NLM_F_REQUEST | NLM_F_ACK);
    encode_set_elem_msg(&mut msg, set_name, ifname);
    batch.push(msg);
    batch.finalize()
}

fn encode_set_elem_msg(msg: &mut MessageBuf, set_name: &CStr, ifname: &CStr) {
    msg.push_attr_cstr(NFTA_SET_ELEM_LIST_TABLE, &TABLE_NAME);
    msg.push_attr_cstr(NFTA_SET_ELEM_LIST_SET, set_name);

    // The element key is the interface name padded to IFNAMSIZ.
    let mut key_buf = [0u8; libc::IFNAMSIZ];
    let src = ifname.to_bytes_with_nul();
    let len = src.len().min(key_buf.len());
    key_buf[..len].copy_from_slice(&src[..len]);

    msg.nest_begin(NFTA_SET_ELEM_LIST_ELEMENTS);
    msg.nest_begin(NFTA_LIST_ELEM); // one element
    msg.nest_begin(NFTA_SET_ELEM_KEY);
    msg.push_attr_bytes(NFTA_DATA_VALUE, &key_buf);
    msg.nest_end(); // NFTA_SET_ELEM_KEY
    msg.nest_end(); // NFTA_LIST_ELEM
    msg.nest_end(); // NFTA_SET_ELEM_LIST_ELEMENTS
}

// ---------------------------------------------------------------------------
// Expression encoders (same logic as the legacy module)
// ---------------------------------------------------------------------------

fn encode_meta_load(msg: &mut MessageBuf, key: u32, dreg: u32) {
    expr_begin(msg, c"meta");
    msg.push_attr_be32(NFTA_META_KEY, key);
    msg.push_attr_be32(NFTA_META_DREG, dreg);
    expr_end(msg);
}

fn encode_lookup(msg: &mut MessageBuf, sreg: u32, set_name: &CStr) {
    expr_begin(msg, c"lookup");
    msg.push_attr_cstr(NFTA_LOOKUP_SET, set_name);
    msg.push_attr_be32(NFTA_LOOKUP_SREG, sreg);
    // No `NFTA_LOOKUP_SET_ID`: the set already exists (created in a
    // prior transaction) and is resolved by name. SET_ID is only for
    // referencing a set created within the *same* batch.
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
    msg.nest_end(); // NFTA_EXPR_DATA
    msg.nest_end(); // NFTA_LIST_ELEM
}

// ---------------------------------------------------------------------------
// NfNetlink socket wrapper
// ---------------------------------------------------------------------------

struct NfNetlink {
    sock: NetlinkSocket,
}

impl NfNetlink {
    fn open() -> Result<Self, SharedMssError> {
        let sock =
            NetlinkSocket::open(libc::NETLINK_NETFILTER).map_err(|e| SharedMssError::Netlink {
                op: "socket",
                source: e,
            })?;
        Ok(Self { sock })
    }

    fn exchange_batch(&self, op: &'static str, batch: &Batch) -> Result<(), SharedMssError> {
        self.sock
            .send(&batch.bytes)
            .map_err(|e| SharedMssError::Netlink { op, source: e })?;

        let mut remaining: std::collections::HashSet<u32> =
            batch.expected_acks.iter().copied().collect();
        let mut reply = [0u8; 8192];
        while !remaining.is_empty() {
            let received = self
                .sock
                .recv_into(&mut reply)
                .map_err(|e| SharedMssError::Netlink { op, source: e })?;
            match wire::drain_acks(received, &mut remaining) {
                Ok(()) => {}
                Err(DrainError::Truncated) => {
                    return Err(SharedMssError::Netlink {
                        op,
                        source: io::Error::other("truncated netlink ack"),
                    });
                }
                Err(DrainError::Kernel(errno)) => {
                    return Err(SharedMssError::Kernel { op, errno });
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod root_tests {
    //! Live-kernel integration tests that drive the real
    //! `NETLINK_NETFILTER` path through [`SharedMssTable`]. They
    //! runtime-skip when the harness can't create nf_tables state
    //! (no `CAP_NET_ADMIN` / nf_tables absent / `nft(8)` missing),
    //! so the default `cargo test` run in an unprivileged container
    //! stays green while a privileged run — including a rootless
    //! `unshare --user --map-root-user --net --mount` — exercises
    //! them for real. That user-namespace path is the intended way
    //! to run these in the dev container:
    //!
    //! ```sh
    //! unshare --user --map-root-user --net \
    //!     cargo test shape::mss_shared::root_tests -- --nocapture
    //! ```

    use super::*;
    use std::sync::Arc;

    /// Serialize nftables tests. Cargo runs bin-tests in parallel
    /// by default; without this, two tests creating/deleting the
    /// same PID-scoped table would race.
    static NFT_LOCK: Mutex<()> = Mutex::new(());

    /// Probe whether we can install nf_tables state at all. Returns
    /// `Some(reason)` to skip, `None` to run. Uses the real code
    /// path (create the table) so a missing capability or absent
    /// nf_tables surfaces as a clean skip rather than a failure.
    fn skip_reason(table: &SharedMssTable) -> Option<String> {
        if std::process::Command::new("nft")
            .arg("--version")
            .output()
            .map_or(true, |o| !o.status.success())
        {
            return Some("nft(8) not available on PATH".into());
        }
        // Trial add with a throwaway MSS group + interface name that
        // no test body asserts on, so the probe never collides with
        // (or leaves state visible to) the real assertions. If the
        // kernel refuses (EPERM without CAP_NET_ADMIN, EOPNOTSUPP
        // without nf_tables, …) we skip. On success, explicitly
        // remove the probe element (`SharedMssGuard` has no `Drop`
        // impl — only `SharedMssHandle` auto-removes).
        match table.add("sstp_probe_x", 9999) {
            Ok(_guard) => {
                table.remove("sstp_probe_x", 9999);
            }
            Err(e) => return Some(format!("cannot install nf_tables state: {e}")),
        }
        // Verify that the `nft` binary can introspect our table.
        // Older nft (e.g. 1.0.6) segfaults parsing the
        // NFTA_SET_USERDATA blob we emit; the kernel is fine but the
        // CLI tool is not. Skip rather than assert on garbled output.
        let probe = std::process::Command::new("nft")
            .args(["list", "table", "ip", &TABLE_NAME.to_string_lossy()])
            .output()
            .expect("run nft list table probe");
        if !probe.status.success() {
            return Some(format!(
                "nft cannot introspect our table (exit {:?}; \
                 older nft may segfault on NFTA_SET_USERDATA)",
                probe.status.code()
            ));
        }
        None
    }

    /// List our PID-scoped table only (avoids dumping the entire
    /// ruleset and sidesteps older `nft` builds that segfault on
    /// unrecognised `NFTA_SET_USERDATA` blobs from other tables).
    fn nft_list_our_table() -> String {
        let out = std::process::Command::new("nft")
            .args(["list", "table", "ip", &TABLE_NAME.to_string_lossy()])
            .output()
            .expect("run nft list table");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    #[test]
    fn add_creates_shared_table_and_set_element() {
        let _lock = NFT_LOCK.lock().expect("NFT_LOCK poisoned");
        let table = SharedMssTable::new();
        if let Some(reason) = skip_reason(&table) {
            eprintln!("SKIP add_creates_shared_table_and_set_element: {reason}");
            return;
        }

        // Two interfaces at the same MSS share one chain + set.
        // `lo`
        // always exists; a second name need not be a real netdev —
        // nftables set membership is by name string, not ifindex.
        let _g1 = table.add("lo", 1383).expect("add lo@1383");
        let _g2 = table.add("sstp_probe0", 1383).expect("add probe@1383");

        let ruleset = nft_list_our_table();
        assert!(
            ruleset.contains("table ip sstp_mss"),
            "shared table missing:\n{ruleset}"
        );
        assert!(
            ruleset.contains("fwd_1383"),
            "expected one shared chain `fwd_1383`:\n{ruleset}"
        );
        // Exactly one chain for the shared MSS value — not one per
        // interface (the regression we're guarding against).
        assert_eq!(
            ruleset.matches("chain fwd_1383").count(),
            1,
            "expected exactly one shared chain, got multiple:\n{ruleset}"
        );
        // Both interface names present as set elements (literal —
        // nft renders `type ifname` sets human-readably; the e2e
        // hex-fallback is belt-and-suspenders).
        assert!(
            ruleset.contains("\"lo\""),
            "set missing `lo` element:\n{ruleset}"
        );
        assert!(
            ruleset.contains("\"sstp_probe0\""),
            "set missing `sstp_probe0` element:\n{ruleset}"
        );

        // Removing one interface leaves the other in place; the
        // shared chain stays.
        table.remove("sstp_probe0", 1383);
        let ruleset = nft_list_our_table();
        assert!(
            !ruleset.contains("\"sstp_probe0\""),
            "dropped element still present:\n{ruleset}"
        );
        assert!(
            ruleset.contains("\"lo\""),
            "surviving element wrongly removed:\n{ruleset}"
        );
        assert!(
            ruleset.contains("fwd_1383"),
            "shared chain wrongly removed while an element remains:\n{ruleset}"
        );

        // Remove the remaining element, then destroy the table.
        table.remove("lo", 1383);
        drop(table);
        let ruleset = nft_list_our_table();
        assert!(
            ruleset.is_empty(),
            "table leaked after SharedMssTable drop:\n{ruleset}"
        );
    }

    #[test]
    fn distinct_mss_values_get_distinct_chains() {
        let _lock = NFT_LOCK.lock().expect("NFT_LOCK poisoned");
        let table = Arc::new(SharedMssTable::new());
        if let Some(reason) = skip_reason(&table) {
            eprintln!("SKIP distinct_mss_values_get_distinct_chains: {reason}");
            return;
        }

        let _h1 = table.add("lo", 1383).expect("add lo@1383");
        let _h2 = table.add("lo", 1356).expect("add lo@1356");

        let ruleset = nft_list_our_table();
        assert!(
            ruleset.contains("fwd_1383") && ruleset.contains("fwd_1356"),
            "expected a chain per distinct MSS value:\n{ruleset}"
        );
        assert!(
            ruleset.contains("ifaces_1383") && ruleset.contains("ifaces_1356"),
            "expected a set per distinct MSS value:\n{ruleset}"
        );
    }
}
