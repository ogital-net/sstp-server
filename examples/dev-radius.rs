//! Tiny in-tree RADIUS authenticator for testing `sstp-server` against
//! real clients without standing up FreeRADIUS.
//!
//! Built on the same `radius-tokio` server surface the e2e tests use,
//! so no new dependencies. Scope is intentionally small: PAP only,
//! Access-Accept carrying `Framed-IP-Address` (and optionally DNS) so
//! the SSTP server's RADIUS bridge has what it needs to bring up an
//! IPCP session. Anything more sophisticated belongs in FreeRADIUS.
//!
//! Run it with:
//!
//! ```sh
//! cargo run --example dev-radius -- \
//!     --listen 0.0.0.0:1812 \
//!     --pool 10.99.0.10-10.99.0.250 \
//!     --secret testing123 \
//!     --dns 1.1.1.1 -v
//! ```
//!
//! Then point the SSTP server at it:
//!
//! ```sh
//! SSTP_RADIUS_SECRET=testing123 \
//!   sstp-server -l 0.0.0.0:443 -c cert.pem -k key.pem \
//!               -r 127.0.0.1:1812 -i 10.99.0.1 -v
//! ```
//!
//! Windows / sstpc clients connecting in PAP mode will land on the
//! next free address in the pool. Auth: by default any username +
//! password is accepted; pass one or more `--user name:password` to
//! restrict to a static list.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use getopt_iter::Getopt;
use radius_tokio::auth::{self, VerifyOutcome};
use radius_tokio::dict::rfc::attrs;
use radius_tokio::server::{
    Client, Handler, HandlerResult, IpCidr, Request, Server, StaticClients,
};
use radius_tokio::{AttributesView, Code};

const OPTSTRING: &str = "l:(listen)s:(secret)p:(pool)d:(dns)u:(user)v+(verbose)qh(help)";
const DEFAULT_LISTEN: &str = "0.0.0.0:1812";
const DEFAULT_SECRET: &str = "testing123";
const DEFAULT_POOL: &str = "10.99.0.10-10.99.0.250";

fn print_help(prog: &str) {
    eprintln!(
        "{prog} — minimal dev RADIUS authenticator (PAP, in-memory pool)

Usage: {prog} [options]

Options:
  -l, --listen <addr>     Listen address (default: {DEFAULT_LISTEN})
  -s, --secret <secret>   Shared secret (default: {DEFAULT_SECRET})
                          Also DEV_RADIUS_SECRET env var.
  -p, --pool <start-end>  IPv4 pool, inclusive (default: {DEFAULT_POOL})
  -d, --dns <addr>        DNS server to advertise (repeatable, max 2)
  -u, --user <name:pass>  Allowed credential (repeatable). When unset,
                          any username/password pair is accepted.
  -v                      Verbose (repeatable: -v, -vv)
  -q                      Quiet (errors only)
  -h, --help              This message

Configure the SSTP server:
  SSTP_RADIUS_SECRET=<secret>
  sstp-server -r <listen-addr> ..."
    );
}

#[derive(Debug, Clone)]
struct Pool {
    start: Ipv4Addr,
    end: Ipv4Addr,
}

impl Pool {
    fn parse(s: &str) -> Result<Self, String> {
        let (a, b) = s
            .split_once('-')
            .ok_or_else(|| format!("--pool: expected START-END, got {s:?}"))?;
        let start: Ipv4Addr = a
            .trim()
            .parse()
            .map_err(|e| format!("--pool start: {e}"))?;
        let end: Ipv4Addr = b.trim().parse().map_err(|e| format!("--pool end: {e}"))?;
        if u32::from(end) < u32::from(start) {
            return Err(format!("--pool: end {end} precedes start {start}"));
        }
        Ok(Self { start, end })
    }
}

#[derive(Debug)]
struct Allocator {
    pool: Pool,
    /// username -> assigned IPv4. Sticky: a returning user gets the
    /// same address until the dev server restarts, which is what
    /// testers typically want.
    by_user: Mutex<HashMap<String, Ipv4Addr>>,
}

impl Allocator {
    fn new(pool: Pool) -> Self {
        Self {
            pool,
            by_user: Mutex::new(HashMap::new()),
        }
    }

    fn assign(&self, user: &str) -> Option<Ipv4Addr> {
        let mut map = self.by_user.lock().expect("allocator mutex poisoned");
        if let Some(ip) = map.get(user) {
            return Some(*ip);
        }
        let in_use: std::collections::HashSet<u32> =
            map.values().map(|ip| u32::from(*ip)).collect();
        let start = u32::from(self.pool.start);
        let end = u32::from(self.pool.end);
        for n in start..=end {
            if !in_use.contains(&n) {
                let ip = Ipv4Addr::from(n);
                map.insert(user.to_string(), ip);
                return Some(ip);
            }
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Verbosity {
    Quiet,
    Default,
    Info,
    Debug,
}

struct PapHandler {
    /// `None` = accept any creds; `Some(map)` = static allowlist
    /// keyed by username, value is the password to compare against.
    users: Option<HashMap<String, Vec<u8>>>,
    allocator: Arc<Allocator>,
    dns: Vec<Ipv4Addr>,
    verbosity: Verbosity,
}

impl Handler for PapHandler {
    async fn handle(&self, request: Request<'_>) -> HandlerResult {
        let src = request.src();
        let code = request.code();
        let id = request.identifier();

        if code != Code::ACCESS_REQUEST {
            if self.verbosity >= Verbosity::Info {
                eprintln!("[{src}] ignoring code={code:?} id={id}");
            }
            return HandlerResult::Drop;
        }

        let username = request
            .first_raw(1)
            .ok()
            .flatten()
            .map(|raw| String::from_utf8_lossy(raw.value()).into_owned())
            .unwrap_or_default();

        let pap_ok = match &self.users {
            None => {
                // Accept-any: just confirm User-Password decoded
                // cleanly against the secret. We don't have a
                // password to compare to, so verify against an
                // empty string and treat any non-Malformed result
                // as success.
                matches!(
                    auth::pap::verify(&request, b""),
                    Ok(VerifyOutcome::Match | VerifyOutcome::Mismatch | VerifyOutcome::Missing)
                )
            }
            Some(map) => match map.get(&username) {
                Some(expected) => {
                    matches!(auth::pap::verify(&request, expected), Ok(VerifyOutcome::Match))
                }
                None => false,
            },
        };

        if !pap_ok {
            if self.verbosity >= Verbosity::Default {
                eprintln!("[{src}] REJECT user={username:?} id={id}");
            }
            return HandlerResult::Reply(request.reply(Code::ACCESS_REJECT));
        }

        let Some(framed_ip) = self.allocator.assign(&username) else {
            eprintln!("[{src}] REJECT user={username:?} id={id} (pool exhausted)");
            return HandlerResult::Reply(request.reply(Code::ACCESS_REJECT));
        };

        let mut reply = request.reply(Code::ACCESS_ACCEPT);
        if let Err(e) = reply.add(attrs::FRAMED_IP_ADDRESS, framed_ip) {
            eprintln!("[{src}] failed to add Framed-IP-Address: {e:?}");
            return HandlerResult::Drop;
        }
        // MS-Primary-DNS-Server / MS-Secondary-DNS-Server are vendor
        // attributes (RFC 2548). We only have rfc attrs imported here
        // to keep the dep surface minimal; clients that need DNS via
        // RADIUS can use Framed-Route or the existing FreeRADIUS
        // setup. Logged for visibility.
        if !self.dns.is_empty() && self.verbosity >= Verbosity::Info {
            eprintln!("[{src}] note: --dns set but MS-VSAs not emitted by dev-radius");
        }

        if self.verbosity >= Verbosity::Default {
            eprintln!("[{src}] ACCEPT user={username:?} ip={framed_ip} id={id}");
        }
        HandlerResult::Reply(reply)
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dev-radius: {e}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn run() -> Result<(), String> {
    let mut getopt = Getopt::new(std::env::args_os(), OPTSTRING);
    getopt.set_opterr(false);
    let prog = getopt.prog_name().to_string();

    let mut listen: String = DEFAULT_LISTEN.to_string();
    let mut secret: Option<String> = None;
    let mut pool_str: String = DEFAULT_POOL.to_string();
    let mut dns: Vec<Ipv4Addr> = Vec::new();
    let mut users: Option<HashMap<String, Vec<u8>>> = None;
    let mut verbose: u32 = 0;
    let mut quiet = false;

    for opt in getopt.by_ref() {
        match opt.val() {
            'h' => {
                print_help(&prog);
                return Ok(());
            }
            'l' => listen = opt.arg().expect("getopt guarantees arg").to_string(),
            's' => secret = Some(opt.arg().expect("getopt guarantees arg").to_string()),
            'p' => pool_str = opt.arg().expect("getopt guarantees arg").to_string(),
            'd' => {
                if dns.len() >= 2 {
                    return Err("--dns: at most two entries".into());
                }
                let s = opt.arg().expect("getopt guarantees arg");
                dns.push(s.parse().map_err(|e| format!("--dns: {e}"))?);
            }
            'u' => {
                let raw = opt.arg().expect("getopt guarantees arg");
                let (name, pass) = raw
                    .split_once(':')
                    .ok_or_else(|| format!("--user: expected NAME:PASS, got {raw:?}"))?;
                users
                    .get_or_insert_with(HashMap::new)
                    .insert(name.to_string(), pass.as_bytes().to_vec());
            }
            'v' => verbose += 1,
            'q' => quiet = true,
            '?' => {
                let bad = opt.erropt().unwrap_or('?');
                return Err(format!("unknown option -{bad}"));
            }
            ':' => {
                let bad = opt.erropt().unwrap_or('?');
                return Err(format!("option -{bad} requires an argument"));
            }
            _ => {}
        }
    }

    if let Some(extra) = getopt.remaining().next() {
        return Err(format!("unexpected positional argument: {extra:?}"));
    }

    let verbosity = if quiet {
        Verbosity::Quiet
    } else {
        match verbose {
            0 => Verbosity::Default,
            1 => Verbosity::Info,
            _ => Verbosity::Debug,
        }
    };

    let pool = Pool::parse(&pool_str)?;
    let allocator = Arc::new(Allocator::new(pool.clone()));

    let secret_bytes = secret
        .or_else(|| std::env::var("DEV_RADIUS_SECRET").ok())
        .unwrap_or_else(|| DEFAULT_SECRET.to_string())
        .into_bytes();

    let bind: SocketAddr = listen.parse().map_err(|e| format!("--listen: {e}"))?;

    // Clients: accept from any source. The dev server is intended for
    // localhost / lab use, so a single 0.0.0.0/0 entry is fine.
    let client = Arc::new(Client::new(secret_bytes.as_slice()));
    let store = StaticClients::builder()
        .add(IpCidr::new(Ipv4Addr::UNSPECIFIED.into(), 0).expect("0.0.0.0/0"), client)
        .build();

    let handler = PapHandler {
        users: users.clone(),
        allocator: Arc::clone(&allocator),
        dns: dns.clone(),
        verbosity,
    };

    let server = Server::builder()
        .clients(store)
        .handler(handler)
        .listen_udp(bind)
        .build()
        .map_err(|e| format!("server build: {e:?}"))?;
    let shutdown = server.shutdown_handle();

    eprintln!(
        "dev-radius: listening on {bind} (pool {}-{}, {} mode)",
        pool.start,
        pool.end,
        if users.is_some() {
            "static-users"
        } else {
            "accept-any"
        }
    );
    if !dns.is_empty() {
        eprintln!("dev-radius: dns hint = {dns:?} (informational only)");
    }

    let task = tokio::spawn(server.run());
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            eprintln!("dev-radius: SIGINT, shutting down");
            shutdown.shutdown();
        }
    }

    match task.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(format!("server task: {e}")),
        Err(e) => Err(format!("server join: {e}")),
    }
}
