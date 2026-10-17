//! `pocket ssh-proxy | ssh | code`: OpenSSH (and editors' remote modes) over vsock. The key
//! pair is pocket's own (`$XDG_DATA_HOME/pocket/ssh/`); the guest's host key is pinned per
//! pocket alias `pocket-<name>`.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;

use pocket_proto::guest::StreamOpen;
use pocket_proto::rpc::{Request, Response};

use crate::client::Client;
use crate::error::{CliError, Result};

pub fn dir() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share")
        })
        .join("pocket/ssh")
}

fn key() -> Result<(PathBuf, String)> {
    let d = dir();
    std::fs::create_dir_all(&d).map_err(|e| CliError::io(&format!("create {}", d.display()), e))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700));
    let k = d.join("id_ed25519");
    if !k.exists() {
        let st = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "pocket", "-f"])
            .arg(&k)
            .status()
            .map_err(|e| {
                CliError::io("run ssh-keygen", e).hint("install OpenSSH (the `ssh` client tools)")
            })?;
        if !st.success() {
            return Err(CliError::new("host_setup", 7, "ssh-keygen failed"));
        }
    }
    let public = std::fs::read_to_string(k.with_extension("pub"))
        .map_err(|e| CliError::io("read the pocket ssh public key", e))?;
    Ok((k, public.trim().to_string()))
}

fn prepare(c: &mut Client, pocket: &str) -> Result<(PathBuf, String, String, PathBuf)> {
    let (k, public) = key()?;
    match c.request(Request::SshPrepare {
        pocket: pocket.into(),
        public_key: public,
    })? {
        Response::Ssh {
            vsock_uds,
            user,
            host_key,
        } => Ok((vsock_uds, user, host_key, k)),
        _ => Err(CliError::new("internal", 70, "unexpected reply")),
    }
}

/// Stdin/stdout ↔ the pocket's sshd: OpenSSH `ProxyCommand`.
pub fn proxy(c: &mut Client, pocket: &str) -> Result<u8> {
    let (uds, ..) = prepare(c, pocket)?;
    let s = crate::vsock::open(&uds, &StreamOpen::PortForward { port: 22 })?;
    let mut up = s.try_clone().map_err(|e| CliError::io("ssh stream", e))?;
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let mut buf = vec![0u8; 64 * 1024];
        while let Ok(n) = stdin.read(&mut buf) {
            if n == 0 || up.write_all(&buf[..n]).is_err() {
                break;
            }
        }
        let _ = up.shutdown(std::net::Shutdown::Write);
    });
    let mut down = &s;
    let mut out = std::io::stdout().lock();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match down.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if out.write_all(&buf[..n]).and_then(|()| out.flush()).is_err() {
                    break;
                }
            }
        }
    }
    Ok(0)
}

fn alias(pocket: &str) -> String {
    format!("pocket-{pocket}")
}

/// known_hosts with this pocket's host key (replacing an older one for the alias).
fn pin(pocket: &str, host_key: &str) -> Result<PathBuf> {
    let kh = dir().join("known_hosts");
    let a = alias(pocket);
    let mut lines: Vec<String> = std::fs::read_to_string(&kh)
        .unwrap_or_default()
        .lines()
        .filter(|l| l.split_whitespace().next() != Some(a.as_str()))
        .map(String::from)
        .collect();
    lines.push(format!("{a} {host_key}"));
    std::fs::write(&kh, lines.join("\n") + "\n")
        .map_err(|e| CliError::io(&format!("write {}", kh.display()), e))?;
    Ok(kh)
}

fn exe() -> String {
    std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "pocket".into())
}

/// `ssh` options that reach `pocket` through the proxy, as `-o` pairs.
fn options(pocket: &str, key: &std::path::Path, known_hosts: &std::path::Path) -> Vec<String> {
    vec![
        format!("ProxyCommand={} ssh-proxy {pocket}", exe()),
        format!("IdentityFile={}", key.display()),
        "IdentitiesOnly=yes".into(),
        format!("UserKnownHostsFile={}", known_hosts.display()),
        "StrictHostKeyChecking=yes".into(),
        "LogLevel=ERROR".into(),
    ]
}

pub fn ssh(c: &mut Client, pocket: &str, command: &[String]) -> Result<u8> {
    let (_, user, host_key, k) = prepare(c, pocket)?;
    let kh = pin(pocket, &host_key)?;
    let mut cmd = Command::new("ssh");
    cmd.arg("-F").arg("/dev/null");
    for o in options(pocket, &k, &kh) {
        cmd.arg("-o").arg(o);
    }
    if command.is_empty() {
        cmd.arg("-t");
    }
    cmd.arg(format!("{user}@{}", alias(pocket))).args(command);
    let st = cmd
        .status()
        .map_err(|e| CliError::io("run ssh", e).hint("install the OpenSSH client"))?;
    Ok(st.code().unwrap_or(255).clamp(0, 255) as u8)
}

/// `~/.ssh/pocket/config` holds a `Host pocket-<name>` block per pocket; `~/.ssh/config`
/// includes it (added once, at the top, so it wins over wildcard hosts).
fn write_config(
    pocket: &str,
    user: &str,
    key: &std::path::Path,
    kh: &std::path::Path,
) -> Result<(PathBuf, bool)> {
    let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    let sshdir = home.join(".ssh");
    let pdir = sshdir.join("pocket");
    std::fs::create_dir_all(&pdir)
        .map_err(|e| CliError::io(&format!("create {}", pdir.display()), e))?;
    let conf = pdir.join("config");
    let a = alias(pocket);
    let old = std::fs::read_to_string(&conf).unwrap_or_default();
    let mut blocks: Vec<String> = old
        .split("\n\n")
        .filter(|b| {
            !b.trim().is_empty()
                && !b
                    .lines()
                    .next()
                    .is_some_and(|l| l.trim() == format!("Host {a}"))
        })
        .map(|b| b.trim().to_string())
        .collect();
    let mut b = format!("Host {a}\n  HostName {a}\n  User {user}\n");
    for o in options(pocket, key, kh) {
        let (k, v) = o.split_once('=').unwrap();
        b.push_str(&format!("  {k} {v}\n"));
    }
    blocks.push(b.trim().to_string());
    std::fs::write(&conf, blocks.join("\n\n") + "\n")
        .map_err(|e| CliError::io(&format!("write {}", conf.display()), e))?;
    let main = sshdir.join("config");
    let text = std::fs::read_to_string(&main).unwrap_or_default();
    let include = "Include pocket/config";
    let added = !text.lines().any(|l| l.trim() == include);
    if added {
        std::fs::write(&main, format!("{include}\n\n{text}"))
            .map_err(|e| CliError::io(&format!("write {}", main.display()), e))?;
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&main, std::fs::Permissions::from_mode(0o600));
    }
    Ok((conf, added))
}

pub fn code(c: &mut Client, pocket: &str, editor: Option<&str>, print: bool) -> Result<u8> {
    let (_, user, host_key, k) = prepare(c, pocket)?;
    let kh = pin(pocket, &host_key)?;
    let (conf, added) = write_config(pocket, &user, &k, &kh)?;
    if added {
        eprintln!("· added `Include pocket/config` to ~/.ssh/config (entries for pocket hosts)");
    }
    let found = |b: &str| {
        std::env::var_os("PATH")
            .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(b).is_file()))
    };
    let editor = match editor {
        Some(e) => e.to_string(),
        None => ["code", "cursor", "zed"]
            .into_iter()
            .find(|b| found(b))
            .unwrap_or("code")
            .to_string(),
    };
    let a = alias(pocket);
    let args: Vec<String> = match editor.as_str() {
        "code" | "cursor" | "codium" => {
            vec!["--remote".into(), format!("ssh-remote+{a}"), "/work".into()]
        }
        "zed" => vec![format!("ssh://{user}@{a}/work")],
        other => {
            return Err(CliError::usage(format!("unknown editor {other:?}"))
                .hint("use --editor code, cursor or zed (or `pocket ssh` for anything else)"));
        }
    };
    if print {
        println!("{editor} {}", args.join(" "));
        println!("# ssh host {a} in {}", conf.display());
        return Ok(0);
    }
    Command::new(&editor).args(&args).spawn().map_err(|e| {
        CliError::io(&format!("start {editor}"), e).hint("install it or pass --editor")
    })?;
    eprintln!("opened {editor} on {a}:/work");
    Ok(0)
}
