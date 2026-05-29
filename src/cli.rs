//! Command-line flag parsing for `sstp-server`.
//!
//! Uses [`getopt-iter`] for POSIX short options + Solaris-style long aliases.
//! Every flag has both a short and a long form, so the parser only ever
//! matches printable ASCII codes and `getopt-iter`'s zero-copy `ArgV`
//! pipeline carries [`std::env::args_os`] straight through — no upfront
//! `Vec<String>` collect.
//!
//! Secrets are read from environment variables (see [`SSTP_RADIUS_SECRET`]
//! and friends), never accepted on the command line. [`dotenvy`] is loaded
//! by `main` before this module is invoked so a developer `.env` populates
//! the environment.

// Most of these fields and constants are consumed in later milestones
// (TLS context, RADIUS bridge, control socket). Allow dead code module-wide
// until M1+ wires them up.
#![allow(dead_code)]

use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::thread::available_parallelism;

use getopt_iter::{ArgV, Getopt};
use thiserror::Error;
use tracing::level_filters::LevelFilter;

pub const SSTP_RADIUS_SECRET: &str = "SSTP_RADIUS_SECRET";
pub const SSTP_RADIUS_ACCT_SECRET: &str = "SSTP_RADIUS_ACCT_SECRET";
pub const SSTP_TLS_KEY_PASSWORD: &str = "SSTP_TLS_KEY_PASSWORD";

const DEFAULT_LISTEN: &str = "[::]:443";
const DEFAULT_CONTROL_SOCKET: &str = "/run/sstp-server.sock";

fn usage(prog: &str) -> String {
    format!(
        "\
{prog} — SSTP (MS-SSTP) server for Linux

USAGE:
    {prog} [OPTIONS] -c <cert> -k <key> -r <host:port>

OPTIONS:
    -l, --listen <addr>          Listen address (default: [::]:443)
    -c, --cert <path>            TLS certificate chain (PEM)
    -k, --key <path>             TLS private key (PEM)
    -r, --radius <host:port>     RADIUS auth server (repeatable)
    -A, --acct <host:port>       RADIUS accounting server (repeatable)
    -t, --threads <n>            I/O worker count (default: auto)
    -T, --auth-threads <n>       Auth runtime threads (default: max(2, ncpus/4))
    -s, --control-socket <path>  Control socket path (default: /run/sstp-server.sock)
    -n, --no-control-socket      Disable the control socket
    -F, --log-format <fmt>       text | json | auto (default: auto)
    -L, --log-file <path>        Log to file instead of stderr
    -D, --data-path <mode>       auto | kernel | tun | userspace (default: auto)
    -i, --local-ip <ipv4>        Server-side IPv4 for every pppN interface (required)
    -u, --user <name>            Drop privileges to this user after binding sockets (root only)
    -g, --group <name>           Group to drop to (defaults to the user's primary GID)
    -v                           Increase verbosity (-v, -vv, -vvv)
    -q, --quiet                  Errors only
    -h, --help                   Print this help and exit
    -V, --version                Print version and exit

ENVIRONMENT:
    SSTP_RADIUS_SECRET           Shared secret for --radius servers
    SSTP_RADIUS_ACCT_SECRET      Shared secret for --acct servers (defaults to SSTP_RADIUS_SECRET)
    SSTP_TLS_KEY_PASSWORD        Passphrase for the TLS private key (optional)
"
    )
}

// Leading ':' enables silent error mode — errors come back as '?'/':' codes
// with `erropt()` set rather than printed to stderr by getopt.
const OPTSTRING: &str = "\
:\
h(help)\
V(version)\
v(verbose)\
q(quiet)\
l:(listen)\
c:(cert)\
k:(key)\
r:(radius)\
A:(acct)\
t:(threads)\
T:(auth-threads)\
s:(control-socket)\
n(no-control-socket)\
F:(log-format)\
L:(log-file)\
D:(data-path)\
i:(local-ip)\
u:(user)\
g:(group)";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
    Auto,
}

/// Operator-selectable data-path mode. `Auto` tries the kernel path
/// first and falls back to a TUN device with a warning log if the
/// `sstp` kmod isn't present or the attach fails. `Userspace` keeps
/// the legacy `/dev/ppp` unit-fd copier — useful for debugging but
/// **does not move IP traffic on mainline kernels** (the unit fd is
/// TX-only and has no attached channel).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DataPathMode {
    #[default]
    Auto,
    Kernel,
    Tun,
    Userspace,
}

/// Parsed configuration. `Result::Ok` here means the daemon should start;
/// the early-exit cases (`--help`, `--version`) return [`ParseOutcome::Exit`].
#[derive(Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub radius: Vec<SocketAddr>,
    pub acct: Vec<SocketAddr>,
    pub io_threads: NonZeroUsize,
    pub auth_threads: NonZeroUsize,
    pub control_socket: Option<PathBuf>,
    pub log_format: LogFormat,
    pub log_file: Option<PathBuf>,
    pub log_level: LevelFilter,
    pub data_path: DataPathMode,
    /// Server-side IPv4 address for every `pppN` interface we bring
    /// up. Required: the kernel needs a P2P address pair to set on
    /// the netdev, and the peer half comes from RADIUS
    /// (`Framed-IP-Address`); the local half has no useful default
    /// at startup.
    pub local_ip: Ipv4Addr,
    /// Unprivileged user to drop to after startup. `None` keeps the
    /// current uid. When set, the daemon must be started as root.
    pub drop_user: Option<String>,
    /// Group to drop to. Defaults to the user's primary group when
    /// `drop_user` is set; ignored when `drop_user` is `None`.
    pub drop_group: Option<String>,
}

#[derive(Debug)]
pub enum ParseOutcome {
    Run(Box<Config>),
    /// User asked for `--help` or `--version`. Caller should print `message`
    /// to stdout and exit with status 0.
    Exit {
        message: String,
    },
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("unknown option: -{0}")]
    UnknownOption(char),
    #[error("missing argument for -{0}")]
    MissingArgument(char),
    #[error("--{flag} is required")]
    MissingRequired { flag: &'static str },
    #[error("invalid value for --{flag}: {value:?}: {source}")]
    InvalidValue {
        flag: &'static str,
        value: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("unexpected positional argument: {0:?}")]
    UnexpectedPositional(String),
    #[error("--threads and --auth-threads must be >= 1")]
    ZeroThreads,
}

impl ParseError {
    fn invalid<E>(flag: &'static str, value: impl Into<String>, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::InvalidValue {
            flag,
            value: value.into(),
            source: Box::new(source),
        }
    }
}

/// Parse argv directly out of any `ArgV`-yielding iterator. Pass
/// [`std::env::args_os`] in production for zero-copy when the OS strings are
/// valid UTF-8; tests pass `&'static str` slices, which are also zero-copy.
///
/// Returns the program name (basename of `argv[0]`) alongside the parse
/// outcome so callers can use the same string in usage hints and error
/// messages regardless of which branch fires.
#[allow(clippy::too_many_lines)]
pub fn parse_args<A, V, I>(args: A) -> (String, Result<ParseOutcome, ParseError>)
where
    A: IntoIterator<Item = V, IntoIter = I>,
    V: ArgV,
    I: Iterator<Item = V>,
{
    let mut getopt = Getopt::new(args, OPTSTRING);
    getopt.set_opterr(false);
    let prog = getopt.prog_name().to_string();
    let result = parse_with(&prog, getopt);
    (prog, result)
}

#[allow(clippy::too_many_lines)]
fn parse_with<V, I>(prog: &str, mut getopt: Getopt<V, I>) -> Result<ParseOutcome, ParseError>
where
    V: ArgV,
    I: Iterator<Item = V>,
{
    let mut listen: Option<String> = None;
    let mut cert: Option<PathBuf> = None;
    let mut key: Option<PathBuf> = None;
    let mut radius: Vec<String> = Vec::new();
    let mut acct: Vec<String> = Vec::new();
    let mut io_threads: Option<usize> = None;
    let mut auth_threads: Option<usize> = None;
    let mut control_socket: Option<PathBuf> = None;
    let mut no_control_socket = false;
    let mut log_format = LogFormat::Auto;
    let mut log_file: Option<PathBuf> = None;
    let mut data_path = DataPathMode::Auto;
    let mut local_ip: Option<String> = None;
    let mut drop_user: Option<String> = None;
    let mut drop_group: Option<String> = None;
    let mut verbose: i32 = 0;
    let mut quiet = false;

    for opt in getopt.by_ref() {
        match opt.val() {
            'h' => {
                return Ok(ParseOutcome::Exit {
                    message: usage(prog),
                });
            }
            'V' => {
                return Ok(ParseOutcome::Exit {
                    message: format!("{prog} {}\n", version_string()),
                });
            }
            'v' => verbose += 1,
            'q' => quiet = true,
            'l' => listen = opt.into_arg().map(std::borrow::Cow::into_owned),
            'c' => cert = opt.into_arg().map(cow_to_path),
            'k' => key = opt.into_arg().map(cow_to_path),
            'r' => {
                if let Some(v) = opt.into_arg() {
                    radius.push(v.into_owned());
                }
            }
            'A' => {
                if let Some(v) = opt.into_arg() {
                    acct.push(v.into_owned());
                }
            }
            't' => io_threads = Some(parse_usize("threads", opt.arg())?),
            'T' => auth_threads = Some(parse_usize("auth-threads", opt.arg())?),
            's' => control_socket = opt.into_arg().map(cow_to_path),
            'n' => no_control_socket = true,
            'F' => {
                let raw = opt.arg().unwrap_or("");
                log_format = match raw {
                    "text" => LogFormat::Text,
                    "json" => LogFormat::Json,
                    "auto" => LogFormat::Auto,
                    other => {
                        return Err(ParseError::invalid(
                            "log-format",
                            other,
                            BadEnumValue("expected one of: text, json, auto"),
                        ));
                    }
                };
            }
            'L' => log_file = opt.into_arg().map(cow_to_path),
            'i' => local_ip = opt.into_arg().map(std::borrow::Cow::into_owned),
            'u' => drop_user = opt.into_arg().map(std::borrow::Cow::into_owned),
            'g' => drop_group = opt.into_arg().map(std::borrow::Cow::into_owned),
            'D' => {
                let raw = opt.arg().unwrap_or("");
                data_path = match raw {
                    "auto" => DataPathMode::Auto,
                    "kernel" => DataPathMode::Kernel,
                    "tun" => DataPathMode::Tun,
                    "userspace" => DataPathMode::Userspace,
                    other => {
                        return Err(ParseError::invalid(
                            "data-path",
                            other,
                            BadEnumValue("expected one of: auto, kernel, tun, userspace"),
                        ));
                    }
                };
            }
            '?' => {
                let bad = opt.erropt().unwrap_or('?');
                return Err(ParseError::UnknownOption(bad));
            }
            ':' => {
                let bad = opt.erropt().unwrap_or('?');
                return Err(ParseError::MissingArgument(bad));
            }
            _ => {}
        }
    }

    if let Some(pos) = getopt.remaining().next() {
        return Err(ParseError::UnexpectedPositional(
            pos.into_argv().into_owned(),
        ));
    }

    let cert = cert.ok_or(ParseError::MissingRequired { flag: "cert" })?;
    let key = key.ok_or(ParseError::MissingRequired { flag: "key" })?;
    if radius.is_empty() {
        return Err(ParseError::MissingRequired { flag: "radius" });
    }
    let local_ip_raw = local_ip.ok_or(ParseError::MissingRequired { flag: "local-ip" })?;
    let local_ip: Ipv4Addr = local_ip_raw
        .parse()
        .map_err(|e| ParseError::invalid("local-ip", local_ip_raw.as_str(), e))?;

    let listen = parse_sockaddr("listen", listen.as_deref().unwrap_or(DEFAULT_LISTEN))?;
    let radius = radius
        .iter()
        .map(|s| parse_sockaddr("radius", s))
        .collect::<Result<Vec<_>, _>>()?;
    let acct = acct
        .iter()
        .map(|s| parse_sockaddr("acct", s))
        .collect::<Result<Vec<_>, _>>()?;

    let (io_threads, auth_threads) = compute_threads(io_threads, auth_threads)?;

    let control_socket = if no_control_socket {
        None
    } else {
        Some(control_socket.unwrap_or_else(|| PathBuf::from(DEFAULT_CONTROL_SOCKET)))
    };

    let log_level = compute_log_level(verbose, quiet);

    Ok(ParseOutcome::Run(Box::new(Config {
        listen,
        cert,
        key,
        radius,
        acct,
        io_threads,
        auth_threads,
        control_socket,
        log_format,
        log_file,
        log_level,
        data_path,
        local_ip,
        drop_user,
        drop_group,
    })))
}

fn cow_to_path(c: std::borrow::Cow<'static, str>) -> PathBuf {
    PathBuf::from(c.into_owned())
}

fn parse_usize(flag: &'static str, raw: Option<&str>) -> Result<usize, ParseError> {
    let raw = raw.unwrap_or("");
    raw.parse::<usize>()
        .map_err(|e| ParseError::invalid(flag, raw, e))
}

fn parse_sockaddr(flag: &'static str, raw: &str) -> Result<SocketAddr, ParseError> {
    raw.parse::<SocketAddr>()
        .map_err(|e| ParseError::invalid(flag, raw, e))
}

fn compute_threads(
    io_override: Option<usize>,
    auth_override: Option<usize>,
) -> Result<(NonZeroUsize, NonZeroUsize), ParseError> {
    let ncpus = available_parallelism().map_or(1, NonZeroUsize::get);
    let auth_default = std::cmp::max(2, ncpus / 4);
    let auth = auth_override.unwrap_or(auth_default);
    let io = io_override.unwrap_or_else(|| ncpus.saturating_sub(auth).max(1));
    let auth_capped = std::cmp::min(auth, io.max(1));
    let io_nz = NonZeroUsize::new(io).ok_or(ParseError::ZeroThreads)?;
    let auth_nz = NonZeroUsize::new(auth_capped).ok_or(ParseError::ZeroThreads)?;
    Ok((io_nz, auth_nz))
}

fn compute_log_level(verbose: i32, quiet: bool) -> LevelFilter {
    if quiet {
        return LevelFilter::ERROR;
    }
    match verbose {
        0 => LevelFilter::WARN,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    }
}

#[derive(Debug, Error)]
#[error("{0}")]
struct BadEnumValue(&'static str);

/// `0.1.0 (abc1234 2026-05-28)` when built from a git checkout, or just
/// `0.1.0` when the build script couldn't reach a `.git` dir.
pub fn version_string() -> String {
    let crate_ver = env!("CARGO_PKG_VERSION");
    match (
        option_env!("VERGEN_GIT_SHA"),
        option_env!("VERGEN_GIT_COMMIT_DATE"),
    ) {
        (Some(sha), Some(date)) if !sha.is_empty() && !date.is_empty() => {
            format!("{crate_ver} ({sha} {date})")
        }
        _ => crate_ver.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&'static str]) -> Result<ParseOutcome, ParseError> {
        parse_args(args.iter().copied()).1
    }

    fn ok_config(args: &[&'static str]) -> Config {
        match run(args).expect("parse ok") {
            ParseOutcome::Run(c) => *c,
            ParseOutcome::Exit { .. } => panic!("expected Run, got Exit"),
        }
    }

    fn min_args() -> Vec<&'static str> {
        vec![
            "sstp-server",
            "-c",
            "/etc/sstp/cert.pem",
            "-k",
            "/etc/sstp/key.pem",
            "-r",
            "127.0.0.1:1812",
            "-i",
            "10.0.0.1",
        ]
    }

    #[test]
    fn help_exits() {
        let out = run(&["sstp-server", "--help"]).unwrap();
        match out {
            ParseOutcome::Exit { message } => assert!(message.contains("USAGE")),
            ParseOutcome::Run(_) => panic!("expected Exit"),
        }
    }

    #[test]
    fn version_exits() {
        let out = run(&["sstp-server", "-V"]).unwrap();
        match out {
            ParseOutcome::Exit { message } => assert!(message.starts_with("sstp-server ")),
            ParseOutcome::Run(_) => panic!("expected Exit"),
        }
    }

    #[test]
    fn minimum_required() {
        let c = ok_config(&min_args());
        assert_eq!(c.cert, PathBuf::from("/etc/sstp/cert.pem"));
        assert_eq!(c.key, PathBuf::from("/etc/sstp/key.pem"));
        assert_eq!(c.radius.len(), 1);
        assert!(c.acct.is_empty());
        assert_eq!(c.log_level, LevelFilter::WARN);
        assert_eq!(c.log_format, LogFormat::Auto);
        assert_eq!(
            c.control_socket.as_deref(),
            Some(std::path::Path::new(DEFAULT_CONTROL_SOCKET))
        );
    }

    #[test]
    fn missing_cert() {
        let err = run(&[
            "sstp-server",
            "-k",
            "/k",
            "-r",
            "1.2.3.4:1812",
            "-i",
            "10.0.0.1",
        ])
        .unwrap_err();
        assert!(matches!(err, ParseError::MissingRequired { flag: "cert" }));
    }

    #[test]
    fn missing_radius() {
        let err = run(&["sstp-server", "-c", "/c", "-k", "/k", "-i", "10.0.0.1"]).unwrap_err();
        assert!(matches!(
            err,
            ParseError::MissingRequired { flag: "radius" }
        ));
    }

    #[test]
    fn missing_local_ip() {
        let err = run(&["sstp-server", "-c", "/c", "-k", "/k", "-r", "1.2.3.4:1812"]).unwrap_err();
        assert!(matches!(
            err,
            ParseError::MissingRequired { flag: "local-ip" }
        ));
    }

    #[test]
    fn verbose_levels() {
        let mut args = min_args();
        args.push("-v");
        assert_eq!(ok_config(&args).log_level, LevelFilter::INFO);
        let mut args = min_args();
        args.push("-vv");
        assert_eq!(ok_config(&args).log_level, LevelFilter::DEBUG);
        let mut args = min_args();
        args.extend_from_slice(&["-v", "-v", "-v"]);
        assert_eq!(ok_config(&args).log_level, LevelFilter::TRACE);
    }

    #[test]
    fn quiet_wins_over_verbose() {
        let mut args = min_args();
        args.extend_from_slice(&["-vv", "-q"]);
        assert_eq!(ok_config(&args).log_level, LevelFilter::ERROR);
    }

    #[test]
    fn no_control_socket_short() {
        let mut args = min_args();
        args.push("-n");
        assert!(ok_config(&args).control_socket.is_none());
    }

    #[test]
    fn no_control_socket_long() {
        let mut args = min_args();
        args.push("--no-control-socket");
        assert!(ok_config(&args).control_socket.is_none());
    }

    #[test]
    fn long_log_format() {
        let mut args = min_args();
        args.extend_from_slice(&["--log-format=json"]);
        assert_eq!(ok_config(&args).log_format, LogFormat::Json);
    }

    #[test]
    fn short_log_format() {
        let mut args = min_args();
        args.extend_from_slice(&["-F", "json"]);
        assert_eq!(ok_config(&args).log_format, LogFormat::Json);
    }

    #[test]
    fn bad_log_format() {
        let mut args = min_args();
        args.extend_from_slice(&["--log-format=yaml"]);
        let err = run(&args).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidValue {
                flag: "log-format",
                ..
            }
        ));
    }

    #[test]
    fn short_auth_threads() {
        let mut args = min_args();
        args.extend_from_slice(&["-T", "4"]);
        assert_eq!(ok_config(&args).auth_threads.get(), 4);
    }

    #[test]
    fn short_control_socket() {
        let mut args = min_args();
        args.extend_from_slice(&["-s", "/tmp/sock"]);
        assert_eq!(
            ok_config(&args).control_socket.as_deref(),
            Some(std::path::Path::new("/tmp/sock"))
        );
    }

    #[test]
    fn repeatable_radius() {
        let mut args = min_args();
        args.extend_from_slice(&["-r", "10.0.0.1:1812", "--radius=10.0.0.2:1812"]);
        let c = ok_config(&args);
        assert_eq!(c.radius.len(), 3);
    }

    #[test]
    fn positional_rejected() {
        let mut args = min_args();
        args.push("extra");
        let err = run(&args).unwrap_err();
        assert!(matches!(err, ParseError::UnexpectedPositional(s) if s == "extra"));
    }

    #[test]
    fn bad_listen() {
        let mut args = min_args();
        args.extend_from_slice(&["-l", "not-an-addr"]);
        let err = run(&args).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidValue { flag: "listen", .. }
        ));
    }
}
