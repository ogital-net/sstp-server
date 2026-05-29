//! TUN-device data path (alternative to `pppN`).
//!
//! Used when the SSTP kmod is not loaded (or kTLS is unavailable so
//! the kmod can't attach). A `tun` netdev is a real bidirectional
//! IP data path: writes inject IP packets into the host stack as
//! ingress on the device, reads return IP packets the stack wants
//! to egress through the device — unlike the `/dev/ppp` unit fd
//! whose `read()` returns EOF on mainline kernels.
//!
//! We expose the same API surface the session task already speaks
//! against the PPP backend: `write_frame` accepts a raw PPP frame
//! (the body of an SSTP data packet), decodes it, and writes the
//! IP payload to the tun fd; `read_frame` reads an IP packet from
//! the tun fd, prepends the PPP protocol field (`0x0021` for IPv4,
//! `0x0057` for IPv6) and returns the encoded PPP frame ready for
//! [`crate::session::write_ppp_as_sstp_data`].

use std::ffi::CString;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use crate::ppp::frame::{ProtocolId, decode_frame, encode_frame};

use super::SessionIpConfig;
use super::netlink::{NetlinkError, RtNetlink};

/// MTU we configure on the tun device. Matches the PPP unit MTU so
/// SSTP data-packet sizing is identical between paths.
const DEFAULT_MTU: u32 = 1500;

const TUN_DEV: &str = "/dev/net/tun";
const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;
const IFNAMSIZ: usize = 16;
const TUNSETIFF: libc::c_ulong = 0x4004_54CA;

#[repr(C)]
struct Ifreq {
    name: [u8; IFNAMSIZ],
    flags: u16,
    _pad: [u8; 22],
}

#[derive(Debug, thiserror::Error)]
pub enum TunError {
    #[error("opening {TUN_DEV}: {0}")]
    Open(#[source] io::Error),
    #[error("TUNSETIFF: {0}")]
    SetIff(#[source] io::Error),
    #[error("setting O_NONBLOCK on tun fd: {0}")]
    Nonblock(#[source] io::Error),
    #[error("resolving ifindex for {ifname}: {source}")]
    ResolveIfindex {
        ifname: String,
        #[source]
        source: io::Error,
    },
    #[error("registering tun fd with tokio: {0}")]
    Register(#[source] io::Error),
    #[error("netlink: {0}")]
    Netlink(#[from] NetlinkError),
}

/// A live TUN-backed session interface.
#[derive(Debug)]
pub struct TunSession {
    ifname: String,
    ifindex: u32,
    async_fd: AsyncFd<OwnedFd>,
}

impl TunSession {
    /// Open `/dev/net/tun`, allocate a new `tunN` interface, push
    /// the local + peer address pair via netlink, and bring it up.
    pub fn bring_up(local: Ipv4Addr, peer: Ipv4Addr) -> Result<Self, TunError> {
        let path = CString::new(TUN_DEV).expect("TUN_DEV has no interior NUL");
        // SAFETY: `path` is a valid NUL-terminated C string for the
        // duration of the call; flags are standard. Returns -1 and
        // sets errno on failure.
        let raw = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if raw < 0 {
            return Err(TunError::Open(io::Error::last_os_error()));
        }
        // SAFETY: `raw` is a fresh open fd we own; nothing else has
        // a copy. Take ownership immediately so a later ? closes it.
        let owned: OwnedFd = unsafe { OwnedFd::from_raw_fd(raw) };

        // Empty name → kernel picks the next free `tunN` and writes
        // the assigned name back into the ifreq.
        let mut req = Ifreq {
            name: [0u8; IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI,
            _pad: [0u8; 22],
        };
        // SAFETY: `owned` is valid; `req` is a valid initialised
        // `ifreq` for the lifetime of the call. TUNSETIFF mutates
        // `req.name` in place to the assigned interface name.
        let rc = unsafe {
            libc::ioctl(
                owned.as_raw_fd(),
                TUNSETIFF as _,
                std::ptr::addr_of_mut!(req),
            )
        };
        if rc < 0 {
            return Err(TunError::SetIff(io::Error::last_os_error()));
        }
        let ifname = parse_ifname(&req.name);

        set_nonblock(owned.as_fd())?;

        let ifindex = resolve_ifindex(&ifname)?;

        let mut nl = RtNetlink::open()?;
        let cfg = SessionIpConfig {
            local,
            peer,
            netmask: None,
            mtu: Some(DEFAULT_MTU),
        };
        nl.bring_up(ifindex, &cfg)?;

        let async_fd = AsyncFd::with_interest(owned, Interest::READABLE | Interest::WRITABLE)
            .map_err(TunError::Register)?;

        Ok(Self {
            ifname,
            ifindex,
            async_fd,
        })
    }

    #[must_use]
    pub fn ifname(&self) -> &str {
        &self.ifname
    }

    #[must_use]
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// Decode `ppp_frame` (the payload of an SSTP `Data` packet),
    /// strip the PPP protocol header, and write the IP body to the
    /// tun fd. Caller must have filtered for IP protocols.
    pub async fn write_frame(&self, ppp_frame: &[u8]) -> io::Result<usize> {
        let parsed = decode_frame(ppp_frame)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if !matches!(
            ProtocolId::from_u16(parsed.protocol),
            Some(ProtocolId::Ip | ProtocolId::Ipv6)
        ) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "write_frame on non-IP PPP protocol 0x{:04x}",
                    parsed.protocol
                ),
            ));
        }
        let body = parsed.info;
        self.async_fd
            .async_io(Interest::WRITABLE, |fd| write_fd(fd.as_fd(), body))
            .await
    }

    /// Read one IP packet from the tun fd and PPP-encode it into
    /// `buf` (uncompressed header: Address + Control + 2-byte
    /// Protocol + payload). `buf` must be at least `4 + MTU`.
    pub async fn read_frame(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut scratch = [0u8; DEFAULT_MTU as usize + 64];
        let n = self
            .async_fd
            .async_io(Interest::READABLE, |fd| read_fd(fd.as_fd(), &mut scratch))
            .await?;
        if n == 0 {
            return Ok(0);
        }
        // RFC 791 §3.1 (IPv4) / RFC 8200 §3 (IPv6) — IP version is
        // the top nibble of byte 0.
        let proto = match scratch[0] >> 4 {
            4 => ProtocolId::Ip,
            6 => ProtocolId::Ipv6,
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("tun returned packet with IP version nibble {other}"),
                ));
            }
        };
        let need = 4 + n;
        if buf.len() < need {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("read_frame buf too small: need {need}, have {}", buf.len()),
            ));
        }
        let written = encode_frame(&mut buf[..need], proto.as_u16(), &scratch[..n]);
        debug_assert_eq!(written, need);
        Ok(written)
    }
}

fn parse_ifname(raw: &[u8; IFNAMSIZ]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

fn resolve_ifindex(ifname: &str) -> Result<u32, TunError> {
    let cstr = CString::new(ifname).expect("ifname has no NUL");
    // SAFETY: `cstr` is a valid NUL-terminated string for the
    // duration of the call; `if_nametoindex` returns 0 on error.
    let idx = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
    if idx == 0 {
        Err(TunError::ResolveIfindex {
            ifname: ifname.to_string(),
            source: io::Error::last_os_error(),
        })
    } else {
        Ok(idx)
    }
}

fn set_nonblock(fd: BorrowedFd<'_>) -> Result<(), TunError> {
    // SAFETY: `fd` is a valid open fd; F_GETFL/F_SETFL are
    // documented signal-safe.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(TunError::Nonblock(io::Error::last_os_error()));
    }
    // SAFETY: as above.
    let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(TunError::Nonblock(io::Error::last_os_error()));
    }
    Ok(())
}

fn write_fd(fd: BorrowedFd<'_>, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: `fd` is valid; `buf` is a valid initialised slice.
    let rc = unsafe { libc::write(fd.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(usize::try_from(rc).expect("non-negative ssize_t"))
    }
}

fn read_fd(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `fd` is valid; `buf` is a valid initialised slice we
    // have exclusive access to.
    let rc = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(usize::try_from(rc).expect("non-negative ssize_t"))
    }
}
