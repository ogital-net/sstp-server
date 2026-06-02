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
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use command_trie::{CommandTrie, CommandTrieBuilder};
use getopt_iter::Getopt;
use nu_ansi_term::{Color, Style};
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::{CmdKind, Highlighter};
use rustyline::hint::Hinter;
use rustyline::history::DefaultHistory;
use rustyline::validate::Validator;
use rustyline::{Context, Editor, Helper};

const DEFAULT_SOCKET: &str = "/run/sstp-server.sock";

/// Static command vocabulary advertised to the operator. Kept
/// deliberately narrower than [`crate::control::dispatch`] supports:
/// `rekey session` is omitted because the cooperative-rekey path is
/// not a stable surface for end users (see `crate::crypto::rekey`).
///
/// `clear` is REPL-local (handled before sending to the daemon).
const COMMANDS: &[(&str, &str)] = &[
    ("help", "show this help"),
    (
        "show info",
        "version, uptime, thread counts, active sessions",
    ),
    ("show stat", "metrics snapshot"),
    ("show session", "list active sessions"),
    ("show session ", "details for a single session by id"),
    ("disable session ", "tear down a session by id"),
    ("shutdown", "ask the daemon to drain and exit"),
    ("clear", "clear the screen"),
    ("quit", "leave the CLI"),
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
    color: bool,
}

impl ReplHelper {
    fn new(color: bool) -> Self {
        Self {
            trie: build_trie(),
            color,
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
        if ext.is_empty() {
            None
        } else {
            Some(ext.to_string())
        }
    }
}

impl Highlighter for ReplHelper {
    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        if self.color {
            Cow::Owned(Style::new().dimmed().paint(hint).to_string())
        } else {
            Cow::Borrowed(hint)
        }
    }

    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(
        &'s self,
        prompt: &'p str,
        _default: bool,
    ) -> Cow<'b, str> {
        if self.color {
            Cow::Owned(Color::Cyan.bold().paint(prompt).to_string())
        } else {
            Cow::Borrowed(prompt)
        }
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
    let color = io::stderr().is_terminal()
        && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
    let bold = if color { Style::new().bold() } else { Style::new() };
    let opt = if color {
        Color::Cyan.into()
    } else {
        Style::new()
    };
    let dim = if color { Style::new().dimmed() } else { Style::new() };

    let mut out = io::stderr().lock();
    let _ = writeln!(
        out,
        "{} {prog} [-S <socket>] [-c <command>]",
        bold.paint("Usage:")
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", bold.paint("Options:"));
    for (flag, desc) in [
        (
            "-S, --socket <path>",
            format!("Control socket (default: {DEFAULT_SOCKET})"),
        ),
        (
            "-c, --command <cmd>",
            "Send a single command and exit (one-shot mode)".to_string(),
        ),
        ("-h, --help", "Print this help".to_string()),
        ("-V, --version", "Print version".to_string()),
    ] {
        // Pad before colouring so the width counts characters, not ANSI bytes.
        let padded = format!("{flag:<22}");
        let _ = writeln!(out, "  {} {}", opt.paint(padded), dim.paint(desc));
    }
}

fn parse_args() -> Result<Args, String> {
    let mut socket = PathBuf::from(DEFAULT_SOCKET);
    let mut one_shot: Option<String> = None;

    let mut opts = Getopt::new(
        std::env::args_os(),
        "S:(socket)c:(command)h(help)V(version)",
    );
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
fn run_one(socket: &Path, cmd: &str, color: bool) -> io::Result<()> {
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
        if acc.ends_with(b"\n\n") {
            acc.truncate(acc.len() - 1);
            break;
        }
    }
    let text = String::from_utf8_lossy(&acc);
    let mut stdout = io::stdout().lock();
    if color {
        write_colored(&mut stdout, &text)?;
    } else {
        stdout.write_all(text.as_bytes())?;
        if !text.ends_with('\n') {
            writeln!(stdout)?;
        }
    }
    Ok(())
}

/// Decorate a daemon response for a TTY. Cheap heuristics keyed off
/// the response shape — the daemon's grammar is line-oriented
/// `key: value` / `Error: ...` / tab-separated tables.
fn write_colored(out: &mut impl Write, text: &str) -> io::Result<()> {
    let key_style = Style::new().dimmed();
    let err_label = Color::Red.bold();
    let err_body: Style = Color::Red.into();
    let header_style = Style::new().bold();
    let ok_label = Color::Green.bold();

    let lines: Vec<&str> = text.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if let Some(rest) = line.strip_prefix("Error: ") {
            writeln!(
                out,
                "{}{}",
                err_label.paint("Error:"),
                err_body.paint(format!(" {rest}"))
            )?;
        } else if line.starts_with("Disconnect queued")
            || line.starts_with("Shutting down")
            || line.starts_with("Rekey queued")
        {
            let (head, tail) = line.split_once(' ').unwrap_or((line, ""));
            writeln!(out, "{} {tail}", ok_label.paint(head))?;
        } else if line.contains('\t') {
            // Bold the first row only — that's the header for show session.
            let style = if i == 0 { header_style } else { Style::new() };
            writeln!(out, "{}", style.paint(*line))?;
        } else if let Some((k, v)) = line.split_once(": ") {
            writeln!(out, "{}: {v}", key_style.paint(k))?;
        } else {
            writeln!(out, "{line}")?;
        }
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

fn run_repl(socket: &Path, color: bool) -> Result<(), Box<dyn std::error::Error>> {
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
    rl.set_helper(Some(ReplHelper::new(color)));

    let history = history_path();
    if let Some(p) = history.as_ref() {
        let _ = rl.load_history(p);
    }

    let banner_path = if color {
        Style::new().bold().paint(socket.display().to_string()).to_string()
    } else {
        socket.display().to_string()
    };
    eprintln!(
        "sstp-server-cli connected to {banner_path}\n\
         Type 'help' for commands, Tab for completion, Ctrl-D to quit."
    );

    let prompt = "sstp> ";
    loop {
        match rl.readline(prompt) {
            Ok(line) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(trimmed);
                match trimmed {
                    "quit" | "exit" => break,
                    "clear" => {
                        // ANSI: cursor home + clear screen.
                        let _ = io::stdout().write_all(b"\x1b[2J\x1b[H");
                        let _ = io::stdout().flush();
                        continue;
                    }
                    _ => {}
                }
                if let Err(e) = run_one(socket, trimmed, color) {
                    let msg = format!("error: {e}");
                    if color {
                        eprintln!("{}", Color::Red.bold().paint(msg));
                    } else {
                        eprintln!("{msg}");
                    }
                }
                if trimmed == "shutdown" {
                    eprintln!("(daemon shutting down; closing REPL)");
                    break;
                }
            }
            Err(ReadlineError::Interrupted) => {
                // Ctrl-C — clear current line, keep going.
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

    let stdout_tty = io::stdout().is_terminal();
    let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
    let color = stdout_tty && !no_color;

    if let Some(cmd) = args.one_shot {
        return match run_one(&args.socket, &cmd, color) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        };
    }

    match run_repl(&args.socket, color) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
