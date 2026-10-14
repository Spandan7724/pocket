//! `pocket`: thin client for pocketd (CLI.md). Every operation is an RPC; attach and exec
//! bytes go straight to the pocket's vsock socket.

mod attach;
mod client;
mod error;
mod exec;
mod term;
mod vsock;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use pocket_proto::rpc::{
    Check, NetEntry, NewPocket, PocketInfo, Request, Response, Topic, Verdict,
};

use crate::client::Client;
use crate::error::{CliError, Result};

#[derive(Parser)]
#[command(
    name = "pocket",
    version,
    about = "Disposable microVM sandboxes for coding agents"
)]
struct Cli {
    /// Machine-readable output.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a pocket (cloning the current repo) and attach to its shell.
    New {
        name: Option<String>,
        #[arg(long)]
        preset: Option<String>,
        /// Repository to clone in (default: the repo containing the current directory).
        #[arg(long, conflicts_with = "no_repo")]
        repo: Option<PathBuf>,
        #[arg(long)]
        no_repo: bool,
        /// Copy uncommitted changes (tracked edits and untracked files) into the pocket.
        #[arg(long)]
        carry: bool,
        #[arg(long)]
        cpus: Option<u8>,
        /// Guest memory, e.g. 4G or 2048M.
        #[arg(long)]
        mem: Option<String>,
        /// Disk quota (sparse), e.g. 20G.
        #[arg(long)]
        disk: Option<String>,
        /// Network profile: dev, strict, offline.
        #[arg(long)]
        net: Option<String>,
        /// Extra allowed destinations (host, *.domain, CIDR, optional :port).
        #[arg(long)]
        allow: Vec<String>,
        /// Create without attaching.
        #[arg(long, short)]
        detach: bool,
        /// Command for the default session instead of a login shell.
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// List pockets.
    Ls,
    /// Attach to a session: POCKET[:SESSION] (default: the most recent session).
    Attach { target: String },
    /// Open a new shell session and attach.
    Sh { pocket: String },
    /// Run a command in a pocket; its exit status becomes ours.
    Exec {
        pocket: String,
        /// Allocate a terminal.
        #[arg(short, long)]
        tty: bool,
        /// Run as root instead of the pocket user.
        #[arg(long)]
        root: bool,
        /// Working directory (default /work).
        #[arg(long, short = 'w')]
        workdir: Option<String>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// List a pocket's sessions.
    Sessions { pocket: String },
    /// Kill a session (POCKET:SESSION); an exited session is forgotten.
    Kill {
        target: String,
        #[arg(long, default_value_t = libc::SIGHUP)]
        signal: i32,
    },
    /// Shut a pocket down (disk kept).
    Stop { pocket: String },
    /// Boot a stopped pocket.
    Start { pocket: String },
    /// Remove pockets with their disks.
    Rm {
        #[arg(required = true)]
        pockets: Vec<String>,
        /// Don't ask for confirmation.
        #[arg(long, short)]
        force: bool,
    },
    /// Show a pocket's network log.
    Logs {
        pocket: String,
        #[arg(long)]
        net: bool,
        #[arg(long, short)]
        follow: bool,
        #[arg(short = 'n', default_value_t = 50)]
        lines: u32,
    },
    /// Build or fetch a preset image (base, claude, codex).
    Pull { preset: String },
    /// Check this host and suggest fixes.
    Doctor,
    /// Manage the daemon.
    Daemon {
        #[command(subcommand)]
        cmd: DaemonCmd,
    },
}

#[derive(Subcommand)]
enum DaemonCmd {
    /// Stop pocketd (pockets keep running and are re-adopted later).
    Stop,
    /// Show whether pocketd runs.
    Status,
}

fn parse_size_mib(s: &str) -> Result<u64> {
    let bad = || CliError::usage(format!("invalid size {s:?}")).hint("use e.g. 4G or 512M");
    let t = s.trim().to_ascii_uppercase();
    let t = t
        .strip_suffix("IB")
        .or_else(|| t.strip_suffix('B'))
        .unwrap_or(&t);
    let (num, mul) = match t.chars().last() {
        Some('T') => (&t[..t.len() - 1], 1024.0 * 1024.0),
        Some('G') => (&t[..t.len() - 1], 1024.0),
        Some('M') => (&t[..t.len() - 1], 1.0),
        _ => (t, 1.0),
    };
    let n: f64 = num.parse().map_err(|_| bad())?;
    if n.is_nan() || n <= 0.0 {
        return Err(bad());
    }
    Ok((n * mul) as u64)
}

/// `POCKET[:SESSION]`.
fn split_target(t: &str) -> (String, Option<String>) {
    match t.split_once(':') {
        Some((p, s)) if !s.is_empty() => (p.to_string(), Some(s.to_string())),
        Some((p, _)) => (p.to_string(), None),
        None => (t.to_string(), None),
    }
}

fn repo_root(start: &Path) -> Option<PathBuf> {
    let mut d = start.to_path_buf();
    loop {
        if d.join(".git").exists() {
            return Some(d);
        }
        if !d.pop() {
            return None;
        }
    }
}

/// `.` = the most recent pocket for the current directory's repository.
fn resolve_pocket(c: &mut Client, p: &str) -> Result<String> {
    if p != "." {
        return Ok(p.to_string());
    }
    let cwd = std::env::current_dir().map_err(|e| CliError::io("current directory", e))?;
    let root = repo_root(&cwd).ok_or_else(|| {
        CliError::usage(
            "`.` means the pocket of the current repository, but this is not a git repository",
        )
    })?;
    let root = root.canonicalize().unwrap_or(root);
    let Response::Pockets(list) = c.request(Request::List)? else {
        return Err(CliError::new("internal", 70, "unexpected reply"));
    };
    list.into_iter()
        .filter(|p| p.repo_path.as_deref() == Some(root.as_path()))
        .max_by_key(|p| p.created_at)
        .map(|p| p.name)
        .ok_or_else(|| {
            CliError::new("not_found", 3, format!("no pocket for {}", root.display()))
                .hint("create one with `pocket new`")
        })
}

fn json<T: serde::Serialize>(v: &T) {
    println!("{}", serde_json::to_string_pretty(v).unwrap());
}

fn human_bytes(b: u64) -> String {
    let units = ["B", "K", "M", "G", "T"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b}B")
    } else {
        format!("{v:.1}{}", units[i])
    }
}

fn ago(ms: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let s = now.saturating_sub(ms) / 1000;
    match s {
        0..=59 => format!("{s}s ago"),
        60..=3599 => format!("{}m ago", s / 60),
        3600..=86399 => format!("{}h ago", s / 3600),
        _ => format!("{}d ago", s / 86400),
    }
}

fn glyph(state: &str) -> &'static str {
    match state {
        "running" => "●",
        "paused" => "‖",
        "hibernated" => "◌",
        "stopped" => "○",
        "creating" => "…",
        _ => "⚠",
    }
}

fn print_pockets(list: &[PocketInfo]) {
    if list.is_empty() {
        println!("no pockets yet — create one with `pocket new`");
        return;
    }
    println!(
        "{:<24} {:<12} {:<8} {:<28} {:>5} {:>7} {:>8}  CREATED",
        "NAME", "STATE", "PRESET", "BRANCH", "CPUS", "MEM", "DISK"
    );
    for p in list {
        let state = p.state.label();
        println!(
            "{:<24} {} {:<10} {:<8} {:<28} {:>5} {:>7} {:>8}  {}",
            p.name,
            glyph(state),
            state,
            p.preset,
            p.branch.as_deref().unwrap_or("-"),
            p.vcpus,
            format!("{}M", p.memory_mib),
            human_bytes(p.disk_used_bytes),
            ago(p.created_at)
        );
        if let pocket_proto::rpc::PocketState::Broken { reason } = &p.state {
            println!("    ⚠ {reason}");
        }
    }
}

fn print_net(e: &NetEntry) {
    let t = e.ts_ms / 1000;
    let (h, m, s) = ((t / 3600) % 24, (t / 60) % 60, t % 60);
    let verdict = match e.verdict {
        Verdict::Allowed => "✓ allowed",
        Verdict::Denied => "✗ BLOCKED",
    };
    let what = match (&e.method, &e.path) {
        (Some(m), Some(p)) => format!("{m} {p}"),
        (Some(m), None) => m.clone(),
        _ => e.kind.clone(),
    };
    let status = e
        .status
        .map(|s| s.to_string())
        .unwrap_or_else(|| "-".into());
    println!(
        "{h:02}:{m:02}:{s:02}Z  {verdict:<10} {:<36} {:<22} {status:>4}  ↑{:<7} ↓{:<7} {}",
        format!("{}:{}", e.host, e.port),
        what.chars().take(22).collect::<String>(),
        human_bytes(e.bytes_up),
        human_bytes(e.bytes_down),
        if e.verdict == Verdict::Denied {
            e.reason.as_str()
        } else {
            ""
        }
    );
}

fn print_checks(checks: &[Check]) -> bool {
    let mut ok = true;
    for c in checks {
        let mark = if !c.ok {
            ok = false;
            "✗"
        } else if c.warn {
            "!"
        } else {
            "✓"
        };
        println!("{mark} {:<14} {}", c.name, c.detail);
        if let Some(f) = &c.fix
            && (!c.ok || c.warn)
        {
            println!("  {:<14} fix: {f}", "");
        }
    }
    ok
}

fn local_checks() -> Vec<Check> {
    let kvm = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm");
    vec![Check {
        name: "kvm".into(),
        ok: kvm.is_ok(),
        warn: false,
        detail: match kvm {
            Ok(_) => "/dev/kvm is read-writable".into(),
            Err(e) => format!("/dev/kvm: {e}"),
        },
        fix: Some(
            "enable virtualization and add yourself to the kvm group: `sudo usermod -aG kvm $USER`"
                .into(),
        ),
    }]
}

fn progress_printer(json: bool) -> impl FnMut(&str) {
    let tty = term::is_tty(2);
    move |stage: &str| {
        if json {
            return;
        }
        if tty {
            eprint!("\r\x1b[2K\x1b[2m· {stage}\x1b[0m");
        } else {
            eprintln!("· {stage}");
        }
        let _ = std::io::stderr().flush();
    }
}

fn end_progress() {
    if term::is_tty(2) {
        eprint!("\r\x1b[2K");
    }
}

fn confirm(question: &str) -> bool {
    if !term::is_tty(0) {
        return false;
    }
    eprint!("{question} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).is_ok() && matches!(s.trim(), "y" | "Y" | "yes")
}

fn run(cli: Cli) -> Result<u8> {
    let j = cli.json;
    match cli.cmd {
        Cmd::Doctor => {
            let checks = match Client::connect() {
                Ok(mut c) => match c.request(Request::Doctor)? {
                    Response::Doctor(v) => v,
                    _ => vec![],
                },
                Err(e) => {
                    let mut v = local_checks();
                    v.push(Check {
                        name: "daemon".into(),
                        ok: false,
                        warn: false,
                        detail: e.message,
                        fix: e.hint,
                    });
                    v
                }
            };
            if j {
                json(&checks);
                return Ok(if checks.iter().all(|c| c.ok) { 0 } else { 1 });
            }
            let ok = print_checks(&checks);
            println!(
                "{}",
                if ok {
                    "\nall checks passed"
                } else {
                    "\nsome checks failed; see the fixes above"
                }
            );
            Ok(if ok { 0 } else { 1 })
        }
        Cmd::Daemon { cmd } => match cmd {
            DaemonCmd::Stop => {
                if let Some(mut c) = Client::connect_existing() {
                    c.request(Request::DaemonStop)?;
                    drop(c);
                    if !Client::wait_daemon_gone(std::time::Duration::from_secs(10)) {
                        return Err(CliError::daemon("pocketd did not exit within 10 s"));
                    }
                    println!("pocketd stopped");
                } else {
                    println!("pocketd is not running");
                }
                Ok(0)
            }
            DaemonCmd::Status => match Client::connect_existing() {
                Some(c) => {
                    println!(
                        "pocketd {} running ({})",
                        c.daemon_version,
                        client::socket_path().display()
                    );
                    Ok(0)
                }
                None => {
                    println!("pocketd is not running");
                    Ok(1)
                }
            },
        },
        cmd => {
            let mut c = Client::connect()?;
            command(&mut c, cmd, j)
        }
    }
}

fn command(c: &mut Client, cmd: Cmd, j: bool) -> Result<u8> {
    match cmd {
        Cmd::New {
            name,
            preset,
            repo,
            no_repo,
            carry,
            cpus,
            mem,
            disk,
            net,
            allow,
            detach,
            command,
        } => {
            let repo = if no_repo {
                None
            } else if let Some(r) = repo {
                Some(
                    r.canonicalize()
                        .map_err(|e| CliError::io(&format!("--repo {}", r.display()), e))?,
                )
            } else {
                let cwd =
                    std::env::current_dir().map_err(|e| CliError::io("current directory", e))?;
                repo_root(&cwd).map(|r| r.canonicalize().unwrap_or(r))
            };
            let req = NewPocket {
                name,
                preset,
                repo,
                carry_changes: carry,
                cpus,
                memory_mib: mem
                    .as_deref()
                    .map(parse_size_mib)
                    .transpose()?
                    .map(|m| m as u32),
                disk_mib: disk.as_deref().map(parse_size_mib).transpose()?,
                net_profile: net,
                allow,
                command: (!command.is_empty()).then_some(command),
                term: std::env::var("TERM").ok(),
            };
            let started = std::time::Instant::now();
            let r = c.request_with(Request::NewPocket(req), progress_printer(j));
            end_progress();
            let Response::Pocket(p) = r? else {
                return Err(CliError::new("internal", 70, "unexpected reply"));
            };
            if j {
                json(&p);
            } else {
                eprintln!(
                    "created {} ({}{}) in {:.1}s",
                    p.name,
                    p.preset,
                    p.branch
                        .as_deref()
                        .map(|b| format!(", branch {b}"))
                        .unwrap_or_default(),
                    started.elapsed().as_secs_f64()
                );
            }
            if detach || j || !term::is_tty(0) {
                if !j {
                    eprintln!("attach with: pocket attach {}", p.name);
                }
                return Ok(0);
            }
            attach::attach(c, &p.name, Some("shell".into()))
        }
        Cmd::Ls => {
            let Response::Pockets(list) = c.request(Request::List)? else {
                return Err(CliError::new("internal", 70, "unexpected reply"));
            };
            if j {
                json(&list)
            } else {
                print_pockets(&list)
            }
            Ok(0)
        }
        Cmd::Attach { target } => {
            let (p, s) = split_target(&target);
            let p = resolve_pocket(c, &p)?;
            attach::attach(c, &p, s)
        }
        Cmd::Sh { pocket } => {
            let p = resolve_pocket(c, &pocket)?;
            let (rows, cols) = term::size();
            let Response::Session { name } = c.request(Request::SessionCreate {
                pocket: p.clone(),
                name: None,
                argv: None,
                rows,
                cols,
                term: std::env::var("TERM").ok(),
            })?
            else {
                return Err(CliError::new("internal", 70, "unexpected reply"));
            };
            attach::attach(c, &p, Some(name))
        }
        Cmd::Exec {
            pocket,
            tty,
            root,
            workdir,
            command,
        } => {
            let p = resolve_pocket(c, &pocket)?;
            let mut env = vec![];
            if tty && let Ok(t) = std::env::var("TERM") {
                env.push(("TERM".to_string(), t));
            }
            let Response::ExecStarted { exec_id, vsock_uds } = c.request(Request::Exec {
                pocket: p,
                argv: command,
                env,
                cwd: workdir,
                tty: tty.then(term::size),
                root,
            })?
            else {
                return Err(CliError::new("internal", 70, "unexpected reply"));
            };
            exec::run(&vsock_uds, exec_id, tty)
        }
        Cmd::Sessions { pocket } => {
            let p = resolve_pocket(c, &pocket)?;
            let Response::Sessions(list) = c.request(Request::SessionList { pocket: p })? else {
                return Err(CliError::new("internal", 70, "unexpected reply"));
            };
            if j {
                json(&list);
            } else {
                println!(
                    "{:<16} {:<12} {:>7} {:>8}  COMMAND",
                    "SESSION", "STATE", "PID", "CLIENTS"
                );
                for s in list {
                    let state = match s.exited {
                        Some(st) => format!("✗ exit {}", st.code()),
                        None => "● running".into(),
                    };
                    println!(
                        "{:<16} {:<12} {:>7} {:>8}  {}",
                        s.name,
                        state,
                        s.pid,
                        s.attached,
                        s.argv.join(" ")
                    );
                }
            }
            Ok(0)
        }
        Cmd::Kill { target, signal } => {
            let (p, s) = split_target(&target);
            let s =
                s.ok_or_else(|| CliError::usage("name the session: pocket kill POCKET:SESSION"))?;
            let p = resolve_pocket(c, &p)?;
            let Response::Sessions(list) = c.request(Request::SessionList { pocket: p.clone() })?
            else {
                return Err(CliError::new("internal", 70, "unexpected reply"));
            };
            let exited = list.iter().any(|x| x.name == s && x.exited.is_some());
            c.request(Request::SessionKill {
                pocket: p.clone(),
                session: s.clone(),
                signal: if exited { 0 } else { signal },
            })?;
            if !j {
                println!(
                    "{} {p}:{s}",
                    if exited {
                        "forgot exited session"
                    } else {
                        "signalled"
                    }
                );
            }
            Ok(0)
        }
        Cmd::Stop { pocket } => {
            let p = resolve_pocket(c, &pocket)?;
            let Response::Pocket(info) = c.request(Request::Stop { pocket: p })? else {
                return Err(CliError::new("internal", 70, "unexpected reply"));
            };
            if j {
                json(&info)
            } else {
                println!("stopped {}", info.name)
            }
            Ok(0)
        }
        Cmd::Start { pocket } => {
            let p = resolve_pocket(c, &pocket)?;
            let Response::Pocket(info) =
                c.request_with(Request::Start { pocket: p }, progress_printer(j))?
            else {
                return Err(CliError::new("internal", 70, "unexpected reply"));
            };
            end_progress();
            if j {
                json(&info)
            } else {
                println!("started {}", info.name)
            }
            Ok(0)
        }
        Cmd::Rm { pockets, force } => {
            for p in pockets {
                let p = resolve_pocket(c, &p)?;
                if !force {
                    let q = format!(
                        "remove {p}? Its disk, sessions and any work not applied to the host are lost"
                    );
                    if !confirm(&q) {
                        return Err(CliError::usage(format!("not removing {p}"))
                            .hint("confirm interactively, or pass --force"));
                    }
                }
                c.request(Request::Remove { pocket: p.clone() })?;
                if !j {
                    println!("removed {p}");
                }
            }
            Ok(0)
        }
        Cmd::Logs {
            pocket,
            net,
            follow,
            lines,
        } => {
            if !net {
                return Err(CliError::usage("only the network log exists so far")
                    .hint("use `pocket logs POCKET --net`"));
            }
            let p = resolve_pocket(c, &pocket)?;
            let Response::NetLog(list) = c.request(Request::NetLog {
                pocket: p.clone(),
                limit: lines,
            })?
            else {
                return Err(CliError::new("internal", 70, "unexpected reply"));
            };
            if j && !follow {
                json(&list);
                return Ok(0);
            }
            for e in &list {
                if j {
                    println!("{}", serde_json::to_string(e).unwrap());
                } else {
                    print_net(e);
                }
            }
            if follow {
                c.subscribe(vec![Topic::Net])?;
                loop {
                    if let pocket_proto::rpc::Event::Net(e) = c.next_event()?
                        && e.pocket == p
                    {
                        if j {
                            println!("{}", serde_json::to_string(&e).unwrap());
                        } else {
                            print_net(&e);
                        }
                        let _ = std::io::stdout().flush();
                    }
                }
            }
            Ok(0)
        }
        Cmd::Pull { preset } => {
            let r = c.request_with(Request::Pull { preset }, progress_printer(j));
            end_progress();
            let Response::Image { name, digest } = r? else {
                return Err(CliError::new("internal", 70, "unexpected reply"));
            };
            if j {
                println!("{}", serde_json::json!({"name": name, "digest": digest}));
            } else {
                println!("{name}: {digest}");
            }
            Ok(0)
        }
        Cmd::Doctor | Cmd::Daemon { .. } => unreachable!(),
    }
}

fn main() -> ExitCode {
    term::mute_signal_default(libc::SIGPIPE);
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            let exit = e.exit;
            eprintln!("{:?}", miette::Report::new(e));
            ExitCode::from(exit)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_targets() {
        assert_eq!(parse_size_mib("4G").unwrap(), 4096);
        assert_eq!(parse_size_mib("512M").unwrap(), 512);
        assert_eq!(parse_size_mib("1.5GiB").unwrap(), 1536);
        assert!(parse_size_mib("lots").is_err() && parse_size_mib("0").is_err());
        assert_eq!(
            split_target("web-1:claude"),
            ("web-1".into(), Some("claude".into()))
        );
        assert_eq!(split_target("web-1"), ("web-1".into(), None));
    }
}
