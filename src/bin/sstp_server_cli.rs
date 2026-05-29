//! `sstp-server-cli` — interactive admin REPL for the sstp-server
//! control socket.
//!
//! Connects to a Unix-domain stream socket (default
//! `/run/sstp-server.sock`) and drives the line-oriented admin
//! protocol from [`crate::control`] in a rustyline session.
//!
//! Fish-style affordances:
//! - dim inline hint extending the current word to the longest
//!   unambiguous completion (powered by `command-trie`),
//! - TAB splices that extension into the buffer; pressing TAB at a
//!   branch point lists candidates,
//! - persistent history at `$XDG_STATE_HOME/sstp-server/history`
//!   (or `~/.local/state/sstp-server/history`).
//!
//! The CLI is a thin client — it sends the typed line verbatim to
//! the daemon and prints the response until the daemon writes a
//! terminator (empty line). `quit` / `exit` / Ctrl-D leave the
//! REPL without touching the daemon; `shutdown` is forwarded and
//! ends the session because the daemon closes the connection.

use std::borrow::Cow;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use command_trie::{CommandTrie, CommandTrieBuilder};
use getopt_iter::Getopt;
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::{CmdKind, Highlighter};
use rustyline::hint::Hinter;
use rustyline::history::DefaultHistory;
use rustyline::validate::Validator;
use rustyline::{Context, Editor, Helper};

const DEFAULT_SOCKET: &str = "/run/sstp-server.sock";
const PROMPT: &str = "sstp> ";

/// Static command vocabulary exposed by the daemon. Keep aligned
/// with `help_text()` in [`sstp_server::control`]. The `&'static str`
/// values are short usage strings shown in help output.
const COMMANDS: &[(&str, &str)] = &[
    ("help", "show this help"),
    ("show info", "version, uptime, thread counts, active sessions"),
    ("show stat", "metrics snapshot"),
    ("show sess", "list active sessions"),
    ("show sess ", "details for a single session by id"),
    ("disable session ", "tear down a session by id"),
    ("shutdown", "ask the daemon to drain and exit"),
];

fn build_trie() -> CommandTrie<&'static str> {
    let mut b = CommandTrieBuilder::new();
    for (cmd, help) in COMMANDS {
        b.insert(cmd, *help);
    }
    b.build()
}

struct ReplHelper {
    trie: CommandTrie<&'static str>,
}

impl ReplHelper {
    fn new() -> Self {
        Self {
            trie: build_trie(),
        }
    }
}

impl Helper for ReplHelper {}

impl Validator for ReplHelper {}

impl Hinter for ReplHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> Option<String> {
        if pos != line.len() || line.is_empty() {
            return None;
        }
        // Don't hint past a whitespace-terminated token unless we have
        // a valid multi-word prefix — `command-trie` will tell us.
        let sub = self.trie.subtrie(line)?;
        let ext = sub.extension();
        if ext.is_empty() { None } else { Some(ext.to_string()) }
    }
}

impl Highlighter for ReplHelper {
    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        // Dim ANSI for fish-style ghost text.
        Cow::Owned(format!("\x1b[2m{hint}\x1b[0m"))
    }

    fn highlight_char(&self, _line: &str, _pos: usize, _kind: CmdKind) -> bool {
        false
    }
}

impl Completer for ReplHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> Result<(usize, Vec<Pair>), ReadlineError> {
        // We complete against the prefix from column 0 to the cursor.
        // Anything past the cursor is treated as not-yet-typed.
        let prefix = &line[..pos];
        let Some(sub) = self.trie.subtrie(prefix) else {
            return Ok((pos, Vec::new()));
        };

        let ext = sub.extension();
        if !ext.is_empty() {
            // Unambiguous extension — splice it.
            return Ok((
                pos,
                vec![Pair {
                    display: ext.to_string(),
                    replacement: ext.to_string(),
                }],
            ));
        }

        // Branch point: enumerate every key that shares this prefix
        // and offer the trailing portion as candidates.
        let mut out = Vec::new();
        sub.for_each(|key, _| {
            if let Some(rest) = key.strip_prefix(prefix) {
                if !rest.is_empty() {
                    out.push(Pair {
                        display: format!("{prefix}{rest}"),
                        replacement: rest.to_string(),
                    });
                }
            }
        });
        Ok((pos, out))
    }
}

#[derive(Debug)]
struct Args {
    socket: PathBuf,
    one_shot: Option<String>,
}

fn print_usage(prog: &str) {
    eprintln!(
        "Usage: {prog} [-S <socket>] [-c <command>]\n\
         \n\
         Options:\n\
         \x20 -S, --socket <path>   Control socket (default: {DEFAULT_SOCKET})\n\
         \x20 -c, --command <cmd>   Send a single command and exit (one-shot mode)\n\
         \x20 -h, --help            Print this help\n\
         \x20 -V, --version         Print version"
    );
}

fn parse_args() -> Result<Args, String> {
    let mut socket = PathBuf::from(DEFAULT_SOCKET);
    let mut one_shot: Option<String> = None;

    let mut opts = Getopt::new(std::env::args_os(), "S:(socket)c:(command)h(help)V(version)");
    opts.set_opterr(false);
    let prog = opts.prog_name().to_string();
    for opt in opts.by_ref() {
        match opt.val() {
            'S' => {
                let s = opt
                    .into_arg()
                    .ok_or_else(|| "-S requires a path".to_string())?;
                socket = PathBuf::from(s.into_owned());
            }
            'c' => {
                let s = opt
                    .into_arg()
                    .ok_or_else(|| "-c requires a command".to_string())?;
                one_shot = Some(s.into_owned());
            }
            'h' => {
                print_usage(&prog);
                std::process::exit(0);
            }
            'V' => {
                println!("sstp-server-cli {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            '?' => return Err("invalid option (try -h)".to_string()),
            c => return Err(format!("unknown option -{c}")),
        }
    }
    Ok(Args { socket, one_shot })
}

/// Send `cmd` on a fresh connection to `socket` and stream the
/// response to stdout. The control protocol terminates each
/// response with a blank line; we read until that or EOF.
fn run_one(socket: &Path, cmd: &str) -> io::Result<()> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(cmd.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let mut buf = [0u8; 4096];
    let mut acc = Vec::with_capacity(1024);
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        acc.extend_from_slice(&buf[..n]);
        // Response terminator: a line containing only "\n" after at
        // least one previous newline. Equivalently: the byte stream
        // ends with "\n\n".
        if acc.ends_with(b"\n\n") {
            // strip the trailing blank line from the operator's view
            acc.truncate(acc.len() - 1);
            break;
        }
    }
    io::stdout().write_all(&acc)?;
    if !acc.ends_with(b"\n") {
        println!();
    }
    Ok(())
}

fn history_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| {
                let mut p = PathBuf::from(h);
                p.push(".local/state");
                p
            })
        })?;
    let mut p = base;
    p.push("sstp-server");
    let _ = std::fs::create_dir_all(&p);
    p.push("history");
    Some(p)
}

fn run_repl(socket: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Quick connectivity check before entering the editor; otherwise
    // every command would surface the same error and the REPL would
    // feel haunted.
    match UnixStream::connect(socket) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("connect {}: {e}", socket.display());
            return Err(e.into());
        }
    }

    let mut rl: Editor<ReplHelper, DefaultHistory> = Editor::new()?;
    rl.set_helper(Some(ReplHelper::new()));

    let history = history_path();
    if let Some(p) = history.as_ref() {
        let _ = rl.load_history(p);
    }

    eprintln!(
        "sstp-server-cli connected to {}\n\
         Type 'help' for commands, Tab for completion, Ctrl-D to quit.",
        socket.display()
    );

    loop {
        match rl.readline(PROMPT) {
            Ok(line) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(trimmed);
                if matches!(trimmed, "quit" | "exit") {
                    break;
                }
                if let Err(e) = run_one(socket, trimmed) {
                    eprintln!("error: {e}");
                }
                if trimmed == "shutdown" {
                    eprintln!("(daemon shutting down; closing REPL)");
                    break;
                }
            }
            Err(ReadlineError::Interrupted) => {
                // Ctrl-C — clear current line, keep going.
                continue;
            }
            Err(ReadlineError::Eof) => break,
            Err(e) => {
                eprintln!("readline: {e}");
                break;
            }
        }
    }

    if let Some(p) = history.as_ref() {
        let _ = rl.save_history(p);
    }
    Ok(())
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };

    if let Some(cmd) = args.one_shot {
        return match run_one(&args.socket, &cmd) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        };
    }

    match run_repl(&args.socket) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
