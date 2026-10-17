//! `pocket`: thin client for pocketd (CLI.md). Every operation is an RPC; attach and exec
//! bytes go straight to the pocket's vsock socket.

mod attach;
mod bench;
mod client;
mod dashboard;
mod diff;
mod error;
mod exec;
mod notice;
mod project;
mod secrets;
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
    /// Without a command: the dashboard.
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
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
        /// Inject only these secrets (repeatable; default: every stored secret).
        #[arg(long = "secret")]
        secrets: Vec<String>,
        /// Inject no secrets.
        #[arg(long, conflicts_with = "secrets")]
        no_secrets: bool,
        /// Copy this secret's REAL value into the pocket instead of a placeholder.
        #[arg(long = "copy-secret")]
        copy_secrets: Vec<String>,
        /// Don't copy host agent config (~/.claude, ~/.codex) into the pocket.
        #[arg(long)]
        no_config: bool,
        /// Forward the host's ssh-agent; every signature needs your approval.
        #[arg(long)]
        ssh_agent: bool,
        /// Environment for every process in the pocket (KEY=VALUE, repeatable).
        #[arg(long = "env", short = 'e')]
        envs: Vec<String>,
        /// Forward GUEST[:HOST] port (repeatable); other ports forward automatically.
        #[arg(long = "forward", short = 'p')]
        forwards: Vec<String>,
        /// Don't forward ports automatically when guest programs listen.
        #[arg(long)]
        no_auto_forward: bool,
        /// Share a host directory into the pocket over virtio-fs: HOST[:GUEST][:ro]
        /// (default /mnt/NAME). The pocket can change these files.
        #[arg(long = "share-dir")]
        share_dirs: Vec<String>,
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
    /// Start a command as a new named session without attaching (e.g. `-- claude`).
    RunIn {
        pocket: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Kill a session (POCKET:SESSION); an exited session is forgotten.
    Kill {
        target: String,
        #[arg(long, default_value_t = libc::SIGHUP)]
        signal: i32,
    },
    /// Shut a pocket down (disk kept).
    Stop { pocket: String },
    /// Boot a stopped pocket (or resume a paused / hibernated one).
    Start { pocket: String },
    /// Freeze a pocket's vCPUs (memory stays; resumes in milliseconds).
    Pause { pocket: String },
    /// Resume a paused or hibernated pocket.
    Resume { pocket: String },
    /// Snapshot a pocket to disk and free its memory; `resume` or any use brings it back.
    Hibernate { pocket: String },
    /// List snapshot templates and the warm pool.
    Templates,
    /// Measure start paths, density and attach latency (JSON with --json).
    Bench {
        #[arg(long, default_value_t = 20)]
        runs: u32,
        #[arg(long, default_value = "base")]
        preset: String,
        /// Idle VMs for the density measurement (0 = skip).
        #[arg(long, default_value_t = 10)]
        density: u32,
        /// Guest memory of the measured VMs (default: the `pocket new` default).
        #[arg(long)]
        mem: Option<String>,
        /// Fail (exit 1) when a p50 is >10% slower than this report from the same host.
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// Also write the JSON report here.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Remove pockets with their disks.
    Rm {
        #[arg(required = true)]
        pockets: Vec<String>,
        /// Don't ask for confirmation.
        #[arg(long, short)]
        force: bool,
    },
    /// Fetch the pocket's work (hardened, into refs/pocket/NAME/*) and show the diff.
    Diff {
        pocket: String,
        /// Include uncommitted changes in the pocket.
        #[arg(long)]
        uncommitted: bool,
        #[arg(long)]
        stat: bool,
    },
    /// Bring the pocket's work into the host repository.
    Apply {
        pocket: String,
        /// One commit with all changes (default).
        #[arg(long, group = "mode")]
        squash: bool,
        /// A merge commit.
        #[arg(long, group = "mode")]
        merge: bool,
        /// The pocket's commits, one by one.
        #[arg(long, group = "mode")]
        cherry_pick: bool,
        /// Switch to this branch first.
        #[arg(long)]
        onto: Option<String>,
        #[arg(long)]
        uncommitted: bool,
        #[arg(long, short)]
        message: Option<String>,
    },
    /// Push the pocket branch from the host and open a pull request.
    Pr {
        pocket: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        body: Option<String>,
        #[arg(long)]
        draft: bool,
        /// Base branch (default: the branch the pocket started from).
        #[arg(long)]
        base: Option<String>,
    },
    /// Bring the host's latest base branch into the pocket.
    Sync {
        pocket: String,
        /// Rebase the pocket branch instead of merging.
        #[arg(long)]
        rebase: bool,
    },
    /// Pending requests that need you: blocked destinations, ssh signatures.
    Approvals { pocket: Option<String> },
    /// Answer a pending request (default: allow once).
    Approve {
        id: u64,
        /// Allow for the pocket's lifetime (network requests).
        #[arg(long)]
        pocket: bool,
        #[arg(long)]
        deny: bool,
    },
    /// Allow destinations for a pocket (host, *.domain, CIDR, optional :port).
    Allow {
        pocket: String,
        #[arg(required = true)]
        hosts: Vec<String>,
        /// Only for the next two minutes.
        #[arg(long)]
        once: bool,
        /// Also add them to the project's pocket.toml.
        #[arg(long)]
        project: bool,
    },
    /// Deny destinations for a pocket.
    Deny {
        pocket: String,
        #[arg(required = true)]
        hosts: Vec<String>,
    },
    /// List port forwards, or forward GUEST[:HOST].
    Port {
        pocket: String,
        spec: Option<String>,
    },
    /// Open a forwarded port in the host browser (default: the only/first one).
    Open { pocket: String, port: Option<u16> },
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
    /// Store a provider credential host-side: claude, openai or github.
    Login {
        provider: String,
        /// Secret name (default: the provider).
        #[arg(long)]
        name: Option<String>,
        /// openai: use the host's Codex login (~/.codex/auth.json).
        #[arg(long)]
        from_codex: bool,
        /// github: use `gh auth token`.
        #[arg(long)]
        from_gh: bool,
    },
    /// Agent config sync: `pocket config pull POCKET` reviews and copies changes back.
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
    /// Manage stored secrets and their destination bindings.
    Secrets {
        #[command(subcommand)]
        cmd: secrets::SecretsCmd,
    },
    /// Check this host and suggest fixes.
    Doctor,
    /// Write a pocket.toml for the current repository (detects the toolchain).
    Init {
        /// Overwrite an existing pocket.toml.
        #[arg(long, short)]
        force: bool,
    },
    /// Manage the daemon.
    Daemon {
        #[command(subcommand)]
        cmd: DaemonCmd,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Show agent config (~/.claude, ~/.codex) changed in a pocket and copy it back after
    /// confirmation.
    Pull {
        pocket: String,
        /// Apply without asking (the diff is still printed).
        #[arg(long, short)]
        yes: bool,
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

/// A `NewPocket` with every option at its default (scripts, bench, dashboard).
fn default_new(name: Option<String>, preset: Option<String>, repo: Option<PathBuf>) -> NewPocket {
    NewPocket {
        name,
        preset,
        repo,
        carry_changes: false,
        cpus: None,
        memory_mib: None,
        disk_mib: None,
        net_profile: None,
        allow: vec![],
        deny: vec![],
        command: None,
        term: std::env::var("TERM").ok(),
        secrets: None,
        copy_secrets: vec![],
        sync_config: true,
        ssh_agent: false,
        auto_forward: true,
        forward: vec![],
        env: vec![],
        git_protected: vec![],
        git_allow_push: vec![],
        setup: None,
        share: vec![],
        idle_pause_ms: None,
        idle_hibernate_ms: None,
        net_mode: None,
        template: None,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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
    let Some(cmd) = cli.cmd else {
        return dashboard::run();
    };
    match cmd {
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
        Cmd::Init { force } => {
            let cwd = std::env::current_dir().map_err(|e| CliError::io("current directory", e))?;
            let root = repo_root(&cwd).unwrap_or(cwd);
            let path = root.join(project::FILE);
            if path.exists() && !force {
                return Err(CliError::new(
                    "already_exists",
                    4,
                    format!("{} exists", path.display()),
                )
                .hint("edit it, or rerun with --force to replace it"));
            }
            let (text, found) = project::detect(&root);
            std::fs::write(&path, &text)
                .map_err(|e| CliError::io(&path.display().to_string(), e))?;
            if j {
                println!("{}", serde_json::json!({ "path": path, "detected": found }));
            } else {
                println!(
                    "wrote {} ({})\nnext: review it, commit it, then `pocket new`",
                    path.display(),
                    if found.is_empty() {
                        "no toolchain detected".into()
                    } else {
                        format!("detected {}", found.join(", "))
                    }
                );
            }
            Ok(0)
        }
        Cmd::Daemon { cmd } => match cmd {
            DaemonCmd::Stop => {
                if let Some(mut c) = Client::connect_existing() {
                    c.request(Request::DaemonStop)?;
                } else if let Some(pid) = Client::listener_pid() {
                    // A pocketd of another RPC version; SIGTERM is its clean shutdown too.
                    // SAFETY: plain kill(2) on a pid owned by our uid.
                    unsafe { libc::kill(pid, libc::SIGTERM) };
                } else {
                    println!("pocketd is not running");
                    return Ok(0);
                }
                if !Client::wait_daemon_gone(std::time::Duration::from_secs(10)) {
                    return Err(CliError::daemon("pocketd did not exit within 10 s"));
                }
                println!("pocketd stopped");
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
                    if let Some(pid) = Client::listener_pid() {
                        println!(
                            "pocketd running (pid {pid}) but speaks another RPC version; \
                             restart it with `pocket daemon stop`"
                        );
                    } else {
                        println!("pocketd is not running");
                    }
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
            secrets,
            no_secrets,
            copy_secrets,
            no_config,
            ssh_agent,
            envs,
            forwards,
            no_auto_forward,
            share_dirs,
            command,
        } => {
            let mut share = vec![];
            for d in share_dirs {
                let mut parts: Vec<&str> = d.split(':').collect();
                let read_only = parts.last() == Some(&"ro");
                if read_only {
                    parts.pop();
                }
                let host = PathBuf::from(parts[0]);
                let guest = parts.get(1).map(|s| s.to_string()).unwrap_or_else(|| {
                    format!(
                        "/mnt/{}",
                        host.file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "share".into())
                    )
                });
                if !read_only && !j {
                    eprintln!(
                        "warning: {} is shared writable: code in the pocket can change or delete these files",
                        host.display()
                    );
                }
                share.push(pocket_proto::rpc::ShareDir {
                    host,
                    guest,
                    read_only,
                });
            }
            let flag_secrets = no_secrets || !secrets.is_empty();
            let mut env = vec![];
            for e in envs {
                let (k, v) = e
                    .split_once('=')
                    .ok_or_else(|| CliError::usage(format!("--env {e:?}: use KEY=VALUE")))?;
                env.push((k.to_string(), v.to_string()));
            }
            let mut forward = vec![];
            for f in forwards {
                forward.push(parse_forward(&f)?);
            }
            if !copy_secrets.is_empty() {
                eprintln!(
                    "warning: --copy-secret puts the real value of {} inside the pocket, where any code can read and send it",
                    copy_secrets.join(", ")
                );
            }
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
                deny: vec![],
                command: (!command.is_empty()).then_some(command),
                term: std::env::var("TERM").ok(),
                secrets: if no_secrets {
                    Some(vec![])
                } else {
                    (!secrets.is_empty()).then_some(secrets)
                },
                copy_secrets,
                sync_config: !no_config,
                ssh_agent,
                auto_forward: !no_auto_forward,
                forward,
                env,
                git_protected: vec![],
                git_allow_push: vec![],
                setup: None,
                share,
                idle_pause_ms: None,
                idle_hibernate_ms: None,
                net_mode: None,
                template: None,
            };
            let mut req = req;
            if let Some(repo) = req.repo.clone()
                && let Some((path, p)) = project::load(&repo)?
            {
                project::apply(&p, &repo, &mut req, flag_secrets)?;
                if !j {
                    eprintln!("· using {}", path.display());
                    for n in &p.notes {
                        eprintln!("  note: {n}");
                    }
                }
            }
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
            let Response::Sessions(list) = c.request(Request::SessionList {
                pocket: p,
                peek: false,
            })?
            else {
                return Err(CliError::new("internal", 70, "unexpected reply"));
            };
            let now = now_ms();
            let states: Vec<_> = list
                .iter()
                .map(|s| pocket_proto::rpc::session_state(s, now))
                .collect();
            if j {
                let v: Vec<serde_json::Value> = list
                    .iter()
                    .zip(&states)
                    .map(|(s, st)| {
                        let mut v = serde_json::to_value(s).unwrap();
                        v["state"] = serde_json::to_value(st).unwrap();
                        v
                    })
                    .collect();
                json(&v);
            } else {
                println!(
                    "{:<16} {:<18} {:>7} {:>8}  COMMAND",
                    "SESSION", "STATE", "PID", "CLIENTS"
                );
                for (s, st) in list.iter().zip(&states) {
                    use pocket_proto::rpc::SessionState as S;
                    let state = match (st, s.exited) {
                        (_, Some(e)) => format!(
                            "{} exit {}",
                            if e.code() == 0 { "✓" } else { "✗" },
                            e.code()
                        ),
                        (S::Working, _) => "● working".into(),
                        (S::Waiting, _) => "○ waiting for input".into(),
                        _ => "· idle".into(),
                    };
                    println!(
                        "{:<16} {:<18} {:>7} {:>8}  {}",
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
        Cmd::RunIn {
            pocket,
            name,
            command,
        } => {
            let p = resolve_pocket(c, &pocket)?;
            let (rows, cols) = term::size();
            let Response::Session { name } = c.request(Request::SessionCreate {
                pocket: p.clone(),
                name,
                argv: Some(command),
                rows,
                cols,
                term: std::env::var("TERM").ok(),
            })?
            else {
                return Err(CliError::new("internal", 70, "unexpected reply"));
            };
            if j {
                json(&serde_json::json!({ "pocket": p, "session": name }));
            } else {
                println!("started {p}:{name} — attach with `pocket attach {p}:{name}`");
            }
            Ok(0)
        }
        Cmd::Kill { target, signal } => {
            let (p, s) = split_target(&target);
            let s =
                s.ok_or_else(|| CliError::usage("name the session: pocket kill POCKET:SESSION"))?;
            let p = resolve_pocket(c, &p)?;
            let Response::Sessions(list) = c.request(Request::SessionList {
                pocket: p.clone(),
                peek: false,
            })?
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
        Cmd::Pause { ref pocket } | Cmd::Resume { ref pocket } | Cmd::Hibernate { ref pocket } => {
            let pocket = resolve_pocket(c, pocket)?;
            let (req, verb) = match cmd {
                Cmd::Pause { .. } => (Request::Pause { pocket }, "paused"),
                Cmd::Resume { .. } => (Request::Resume { pocket }, "resumed"),
                _ => (Request::Hibernate { pocket }, "hibernated"),
            };
            let started = std::time::Instant::now();
            let Response::Pocket(info) = c.request(req)? else {
                return Err(CliError::new("internal", 70, "unexpected reply"));
            };
            if j {
                json(&info)
            } else {
                println!(
                    "{verb} {} in {:.0} ms",
                    info.name,
                    started.elapsed().as_secs_f64() * 1e3
                )
            }
            Ok(0)
        }
        Cmd::Bench {
            runs,
            preset,
            density,
            mem,
            baseline,
            out,
        } => {
            let mem = mem
                .as_deref()
                .map(parse_size_mib)
                .transpose()?
                .map(|m| m as u32);
            let report = bench::run(c, runs, &preset, density, mem, progress_printer(j))?;
            if let Some(o) = &out {
                std::fs::write(o, serde_json::to_string_pretty(&report).unwrap())
                    .map_err(|e| CliError::io(&format!("write {}", o.display()), e))?;
            }
            if j {
                json(&report);
            } else {
                bench::print(&report);
            }
            if let Some(b) = baseline {
                let reg = bench::regressions(&report, &b)?;
                if !reg.is_empty() {
                    for r in &reg {
                        eprintln!("✗ regression: {r}");
                    }
                    return Ok(1);
                }
                eprintln!("✓ no regression > 10% against {}", b.display());
            }
            Ok(0)
        }
        Cmd::Templates => {
            let Response::Templates(list) = c.request(Request::Templates)? else {
                return Err(CliError::new("internal", 70, "unexpected reply"));
            };
            let Response::Pool(pool) = c.request(Request::Pool)? else {
                return Err(CliError::new("internal", 70, "unexpected reply"));
            };
            if j {
                json(&serde_json::json!({ "templates": list, "pool": pool }));
                return Ok(0);
            }
            if list.is_empty() {
                println!("no templates yet — the first `pocket new` of a preset builds one");
            } else {
                println!(
                    "{:<22} {:<8} {:<10} {:>4} {:>7} {:>8}  BUILT",
                    "KEY", "KIND", "PRESET", "CPUS", "MEM", "SIZE"
                );
                for t in &list {
                    println!(
                        "{:<22} {:<8} {:<10} {:>4} {:>7} {:>8}  {}",
                        t.name.clone().unwrap_or_else(|| t.key.clone()),
                        t.kind,
                        t.preset,
                        t.vcpus,
                        format!("{}M", t.memory_mib),
                        human_bytes(t.size_bytes),
                        ago(t.built_at)
                    );
                }
            }
            println!(
                "pool: {} ({} of {} ready, {} MiB of {} MiB cap{})",
                if pool.enabled { "on" } else { "off" },
                pool.ready,
                pool.size,
                pool.memory_mib,
                pool.max_total_memory_mib,
                pool.template
                    .as_deref()
                    .map(|t| format!(", template {t}"))
                    .unwrap_or_default()
            );
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
        Cmd::Diff {
            pocket,
            uncommitted,
            stat,
        } => {
            let p = resolve_pocket(c, &pocket)?;
            let color = !j && term::is_tty(1) && std::env::var_os("NO_COLOR").is_none();
            let r = c.request_with(
                Request::Diff {
                    pocket: p,
                    uncommitted,
                    stat,
                    color,
                },
                progress_printer(j),
            );
            end_progress();
            let Response::Text { text, .. } = r? else {
                return Err(CliError::new("internal", 70, "unexpected reply"));
            };
            if j {
                println!("{}", serde_json::json!({ "diff": text }));
            } else if text.is_empty() {
                println!("no changes");
            } else {
                print!("{text}");
            }
            Ok(0)
        }
        Cmd::Apply {
            pocket,
            squash: _,
            merge,
            cherry_pick,
            onto,
            uncommitted,
            message,
        } => {
            let p = resolve_pocket(c, &pocket)?;
            let mode = if merge {
                pocket_proto::rpc::ApplyMode::Merge
            } else if cherry_pick {
                pocket_proto::rpc::ApplyMode::CherryPick
            } else {
                pocket_proto::rpc::ApplyMode::Squash
            };
            text_reply(
                c.request(Request::Apply {
                    pocket: p,
                    mode,
                    onto,
                    uncommitted,
                    message,
                })?,
                j,
            )
        }
        Cmd::Pr {
            pocket,
            title,
            body,
            draft,
            base,
        } => {
            let p = resolve_pocket(c, &pocket)?;
            text_reply(
                c.request(Request::Pr {
                    pocket: p,
                    title,
                    body,
                    draft,
                    base,
                })?,
                j,
            )
        }
        Cmd::Sync { pocket, rebase } => {
            let p = resolve_pocket(c, &pocket)?;
            text_reply(c.request(Request::Sync { pocket: p, rebase })?, j)
        }
        Cmd::Approvals { pocket } => {
            let pocket = pocket.map(|p| resolve_pocket(c, &p)).transpose()?;
            let Response::Approvals(list) = c.request(Request::Approvals { pocket })? else {
                return Err(CliError::new("internal", 70, "unexpected reply"));
            };
            if j {
                json(&list);
            } else if list.is_empty() {
                println!("nothing is waiting for you");
            } else {
                println!("{:>5}  {:<20} REQUEST", "ID", "POCKET");
                for a in &list {
                    println!("{:>5}  {:<20} {}", a.id, a.pocket, describe_approval(a));
                }
                println!("\nanswer with `pocket approve ID [--pocket|--deny]`");
            }
            Ok(0)
        }
        Cmd::Approve { id, pocket, deny } => {
            let decision = if deny {
                pocket_proto::rpc::Decision::Deny
            } else if pocket {
                pocket_proto::rpc::Decision::Pocket
            } else {
                pocket_proto::rpc::Decision::Once
            };
            c.request(Request::Approve { id, decision })?;
            if !j {
                println!("{} request {id}", if deny { "denied" } else { "approved" });
            }
            Ok(0)
        }
        Cmd::Allow {
            pocket,
            hosts,
            once,
            project,
        } => {
            let p = resolve_pocket(c, &pocket)?;
            c.request(Request::NetAllow {
                pocket: p.clone(),
                hosts: hosts.clone(),
                once,
            })?;
            if project {
                let path = project::allow_in_project(c, &p, &hosts)?;
                if !j {
                    println!("added {} to {}", hosts.join(", "), path.display());
                }
            }
            if !j {
                println!(
                    "allowed {} for {p}{}",
                    hosts.join(", "),
                    if once { " (two minutes)" } else { "" }
                );
            }
            Ok(0)
        }
        Cmd::Deny { pocket, hosts } => {
            let p = resolve_pocket(c, &pocket)?;
            c.request(Request::NetDeny {
                pocket: p.clone(),
                hosts: hosts.clone(),
            })?;
            if !j {
                println!("denied {} for {p}", hosts.join(", "));
            }
            Ok(0)
        }
        Cmd::Port { pocket, spec } => {
            let p = resolve_pocket(c, &pocket)?;
            let r = match spec {
                Some(s) => {
                    let (g, h) = parse_forward(&s)?;
                    c.request(Request::PortAdd {
                        pocket: p,
                        guest: g,
                        host: s.contains(':').then_some(h),
                    })?
                }
                None => c.request(Request::Ports { pocket: p })?,
            };
            let Response::Ports(list) = r else {
                return Err(CliError::new("internal", 70, "unexpected reply"));
            };
            if j {
                json(&list);
            } else if list.is_empty() {
                println!(
                    "no forwarded ports — programs listening in the pocket are forwarded automatically"
                );
            } else {
                println!("{:>6}  {:<22} {:<6} PROCESS", "GUEST", "HOST", "AUTO");
                for f in list {
                    println!(
                        "{:>6}  127.0.0.1:{:<12} {:<6} {}",
                        f.guest,
                        f.host,
                        if f.auto { "yes" } else { "no" },
                        f.process.unwrap_or_default()
                    );
                }
            }
            Ok(0)
        }
        Cmd::Open { pocket, port } => {
            let p = resolve_pocket(c, &pocket)?;
            let Response::Ports(list) = c.request(Request::Ports { pocket: p.clone() })? else {
                return Err(CliError::new("internal", 70, "unexpected reply"));
            };
            let f = match port {
                Some(g) => list.iter().find(|f| f.guest == g),
                None => list.first(),
            }
            .ok_or_else(|| {
                CliError::new(
                    "not_found",
                    3,
                    format!(
                        "no forwarded port{} in {p}",
                        port.map(|x| format!(" {x}")).unwrap_or_default()
                    ),
                )
                .hint(format!(
                    "`pocket port {p}` lists forwards; start a server in the pocket first"
                ))
            })?;
            let url = format!("http://127.0.0.1:{}/", f.host);
            open_browser(&url)?;
            if j {
                println!("{}", serde_json::json!({ "url": url }));
            } else {
                println!("opened {url} (guest port {})", f.guest);
            }
            Ok(0)
        }
        Cmd::Login {
            provider,
            name,
            from_codex,
            from_gh,
        } => secrets::login(c, &provider, name, from_codex, from_gh, j),
        Cmd::Secrets { cmd } => secrets::secrets(c, cmd, j),
        Cmd::Config {
            cmd: ConfigCmd::Pull { pocket, yes },
        } => config_pull(c, &pocket, yes, j),
        Cmd::Doctor | Cmd::Daemon { .. } | Cmd::Init { .. } => unreachable!(),
    }
}

/// `GUEST[:HOST]`.
fn parse_forward(s: &str) -> Result<(u16, u16)> {
    let bad = || {
        CliError::usage(format!("invalid port forward {s:?}"))
            .hint("use GUEST or GUEST:HOST, e.g. 5173 or 3000:8080")
    };
    let (g, h) = s.split_once(':').unwrap_or((s, s));
    let g: u16 = g.parse().map_err(|_| bad())?;
    let h: u16 = h.parse().map_err(|_| bad())?;
    if g == 0 || h == 0 {
        return Err(bad());
    }
    Ok((g, h))
}

fn describe_approval(a: &pocket_proto::rpc::ApprovalInfo) -> String {
    match &a.what {
        pocket_proto::rpc::ApprovalWhat::Network { host, port, reason } => format!(
            "network  {}{}  ({reason})",
            host,
            port.map(|p| format!(":{p}")).unwrap_or_default()
        ),
        pocket_proto::rpc::ApprovalWhat::SshSign { key, comment } => {
            format!("ssh sign  key {key} {comment}")
        }
        pocket_proto::rpc::ApprovalWhat::File { path } => {
            format!("copy host file {path} into the pocket")
        }
    }
}

fn open_browser(url: &str) -> Result<()> {
    let cmd = std::env::var("POCKET_OPEN_CMD").unwrap_or_else(|_| "xdg-open".into());
    std::process::Command::new(&cmd)
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|e| CliError::io(&format!("run {cmd}"), e).hint(format!("open {url} yourself")))
}

fn text_reply(r: Response, j: bool) -> Result<u8> {
    let Response::Text { text, url } = r else {
        return Err(CliError::new("internal", 70, "unexpected reply"));
    };
    if j {
        println!("{}", serde_json::json!({ "message": text, "url": url }));
    } else {
        println!("{}", text.trim_end());
    }
    Ok(0)
}

fn config_pull(c: &mut Client, pocket: &str, yes: bool, j: bool) -> Result<u8> {
    let p = resolve_pocket(c, pocket)?;
    let Response::ConfigChanges(changes) = c.request(Request::ConfigPull {
        pocket: p.clone(),
        accept: None,
    })?
    else {
        return Err(CliError::new("internal", 70, "unexpected reply"));
    };
    if j && !yes {
        json(&changes);
        return Ok(0);
    }
    if changes.is_empty() {
        if !j {
            println!("agent config in {p} matches the host");
        }
        return Ok(0);
    }
    if !j {
        println!(
            "Agent config changed in {p}. Config from a pocket can run commands on this machine \
             (hooks, MCP servers, status line): review every line.\n"
        );
        for ch in &changes {
            let state = if ch.host.is_none() { "new" } else { "modified" };
            println!("── ~/{} ({state})", ch.path);
            if !ch.risky.is_empty() {
                println!("   ⚠ touches: {}", ch.risky.join(", "));
            }
            if let Some(b) = &ch.blocked {
                println!("   ✗ skipped: {b}");
                continue;
            }
            print!(
                "{}",
                diff::unified(ch.host.as_deref().unwrap_or(""), &ch.guest, 3)
            );
            println!();
        }
    }
    let ok: Vec<_> = changes.iter().filter(|ch| ch.blocked.is_none()).collect();
    if ok.is_empty() {
        return Ok(0);
    }
    if !yes
        && !confirm(&format!(
            "copy {} file(s) to your home directory?",
            ok.len()
        ))
    {
        return Err(CliError::usage("nothing copied")
            .hint("confirm interactively, or pass --yes after reviewing the diff"));
    }
    let Response::ConfigChanges(written) = c.request(Request::ConfigPull {
        pocket: p,
        accept: Some(
            ok.iter()
                .map(|ch| (ch.path.clone(), ch.sha256.clone()))
                .collect(),
        ),
    })?
    else {
        return Err(CliError::new("internal", 70, "unexpected reply"));
    };
    if j {
        json(&written);
    } else {
        for w in written {
            println!("wrote ~/{}", w.path);
        }
    }
    Ok(0)
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
