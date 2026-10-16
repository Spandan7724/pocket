//! Opt-in shared host directories (`pocket new --share-dir`) over virtio-fs, one virtiofsd
//! per share. Visibly flagged and never allowed to expose a git directory (D5): sharing a
//! repository would let the guest plant hooks that run on the host.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use pocket_proto::rpc::{ErrorCode, ShareDir};
use tokio::task::JoinHandle;

use crate::daemon::{R, err};
use crate::guest::GuestConn;
use crate::paths::Paths;

const RESERVED: &[&str] = &[
    "/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/run", "/sbin", "/sys",
    "/usr", "/var", "/work", "/home", "/root", "/tmp",
];

fn has_git(dir: &Path, depth: u32) -> bool {
    if dir.join(".git").exists() {
        return true;
    }
    depth > 0
        && std::fs::read_dir(dir).is_ok_and(|rd| {
            rd.flatten()
                .any(|e| e.file_type().is_ok_and(|t| t.is_dir()) && has_git(&e.path(), depth - 1))
        })
}

pub fn validate(shares: &[ShareDir]) -> R<Vec<ShareDir>> {
    let mut out = vec![];
    for s in shares {
        let host = s.host.canonicalize().map_err(|e| {
            err(
                ErrorCode::BadRequest,
                format!("--share-dir {}: {e}", s.host.display()),
            )
        })?;
        if !host.is_dir() {
            return Err(err(
                ErrorCode::BadRequest,
                format!("{} is not a directory", host.display()),
            ));
        }
        if host.ancestors().any(|a| a.join(".git").exists()) || has_git(&host, 3) {
            return Err(err(
                ErrorCode::BadRequest,
                format!("{} is or contains a git repository", host.display()),
            )
            .hint("repositories are cloned into pockets, never shared (a pocket could plant git hooks that run on your machine); share a data directory instead"));
        }
        let home = std::env::var_os("HOME").map(PathBuf::from);
        if Some(&host) == home.as_ref() || host == Path::new("/") {
            return Err(err(
                ErrorCode::BadRequest,
                format!("refusing to share {}", host.display()),
            )
            .hint("share a specific directory, not your home or the root"));
        }
        let guest = s.guest.trim_end_matches('/').to_string();
        let ok = guest.starts_with('/')
            && !guest.split('/').any(|c| c == "..")
            && !RESERVED.contains(&guest.as_str())
            && guest
                .bytes()
                .all(|b| b.is_ascii_graphic() && b != b'\'' && b != b'"');
        if !ok {
            return Err(err(
                ErrorCode::BadRequest,
                format!("invalid guest path {:?}", s.guest),
            )
            .hint("use an absolute path such as /mnt/data (not a system directory or /work)"));
        }
        out.push(ShareDir {
            host,
            guest,
            read_only: s.read_only,
        });
    }
    Ok(out)
}

fn virtiofsd(paths: &Paths) -> Option<PathBuf> {
    let bundled = paths.tool("virtiofsd");
    if bundled.is_absolute() && bundled.exists() {
        return Some(bundled);
    }
    for p in [
        "/usr/lib/virtiofsd",
        "/usr/libexec/virtiofsd",
        "/usr/bin/virtiofsd",
    ] {
        if Path::new(p).exists() {
            return Some(p.into());
        }
    }
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|d| d.join("virtiofsd"))
            .find(|p| p.exists())
    })
}

fn supports(bin: &Path, opt: &str) -> bool {
    std::process::Command::new(bin)
        .arg("--help")
        .output()
        .is_ok_and(|h| String::from_utf8_lossy(&h.stdout).contains(opt))
}

/// Starts virtiofsd for share `i`; it exits when the VMM disconnects.
pub async fn start_virtiofsd(
    paths: &Paths,
    rt: &Path,
    i: usize,
    s: &ShareDir,
) -> R<(PathBuf, JoinHandle<()>)> {
    let bin = virtiofsd(paths).ok_or_else(|| {
        err(
            ErrorCode::HostSetup,
            "virtiofsd is not installed (needed for --share-dir)",
        )
        .hint("install it (Arch: virtiofsd, Debian/Ubuntu: virtiofsd) or drop --share-dir")
    })?;
    if s.read_only && !supports(&bin, "--readonly") {
        return Err(err(
            ErrorCode::HostSetup,
            format!(
                "{} has no --readonly option, needed for a read-only share",
                bin.display()
            ),
        )
        .hint("upgrade virtiofsd (1.11 or newer), or share the directory writable"));
    }
    let sock = rt.join(format!("fs{i}.sock"));
    // An unprivileged user namespace confines virtiofsd to the shared directory; fall back to
    // no sandbox only where namespaces are unavailable.
    for sandbox in ["namespace", "none"] {
        let _ = std::fs::remove_file(&sock);
        let mut c = tokio::process::Command::new(&bin);
        c.arg("--socket-path")
            .arg(&sock)
            .arg("--shared-dir")
            .arg(&s.host)
            .args([
                "--sandbox",
                sandbox,
                "--cache",
                "auto",
                "--log-level",
                "error",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(false);
        if s.read_only {
            c.arg("--readonly");
        }
        // The guest's `dev` user is uid/gid 1000; map it to the host user so it owns what
        // it sees (older virtiofsd can't, and the share is then writable by guest root only).
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        if (uid != 1000 || gid != 1000) && supports(&bin, "--translate-uid") {
            c.arg("--translate-uid")
                .arg(format!("map:1000:{uid}:1"))
                .arg("--translate-gid")
                .arg(format!("map:1000:{gid}:1"));
        }
        let mut child = c.spawn().map_err(|e| {
            err(
                ErrorCode::HostSetup,
                format!("start {}: {e}", bin.display()),
            )
        })?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while !sock.exists() && Instant::now() < deadline {
            if let Ok(Some(_)) = child.try_wait() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if sock.exists() {
            if sandbox == "none" {
                tracing::warn!(
                    "virtiofsd for {} runs without a namespace sandbox (unprivileged user namespaces unavailable)",
                    s.host.display()
                );
            }
            let task = tokio::spawn(async move {
                let _ = child.wait().await;
            });
            return Ok((sock, task));
        }
        let _ = child.kill().await;
    }
    Err(err(
        ErrorCode::HostSetup,
        format!("virtiofsd for {} did not start", s.host.display()),
    ))
}

pub async fn mount_all(guest: &GuestConn, shares: &[ShareDir]) -> R<()> {
    for (i, s) in shares.iter().enumerate() {
        crate::provision::sh_args(
            guest,
            None,
            "mkdir -p \"$2\" && { mountpoint -q \"$2\" || mount -t virtiofs \"$1\" \"$2\" -o \"$3\"; }",
            &[
                &format!("pocketfs{i}"),
                &s.guest,
                if s.read_only { "ro" } else { "rw" },
            ],
            vec![],
            "mount shared directory",
        )
        .await?;
    }
    Ok(())
}
