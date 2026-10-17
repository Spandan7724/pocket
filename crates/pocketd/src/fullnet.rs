//! `--net full` (D6's explicit escape hatch): a virtio-net NIC served by passt over
//! vhost-user. Traffic that ignores the proxy variables leaves unfiltered; pocket flags such
//! pockets everywhere. passt never maps the host's loopback (`--no-map-gw`).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use pocket_proto::rpc::ErrorCode;
use tokio::task::JoinHandle;

use crate::daemon::{R, err};
use crate::paths::Paths;

/// Guest addressing (fixed; passt NATs it to the host's own connections).
pub const GUEST_ADDR: &str = "10.0.2.15";
pub const GATEWAY: &str = "10.0.2.2";
pub const DNS: &str = "10.0.2.3";

fn passt(paths: &Paths) -> Option<PathBuf> {
    let bundled = paths.tool("passt");
    if bundled.is_absolute() && bundled.exists() {
        return Some(bundled);
    }
    std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join("passt"))
            .find(|c| c.is_file())
    })
}

pub async fn start(paths: &Paths, rt: &Path) -> R<(PathBuf, JoinHandle<()>)> {
    let bin = passt(paths).ok_or_else(|| {
        err(
            ErrorCode::HostSetup,
            "passt is not installed (needed for --net full)",
        )
        .hint("install passt (Arch/Debian/Fedora package `passt`) or use the proxy (default)")
    })?;
    let sock = rt.join("passt.sock");
    let _ = std::fs::remove_file(&sock);
    let mut child = tokio::process::Command::new(&bin)
        .args([
            "--vhost-user",
            "--foreground",
            "--quiet",
            "--ipv4-only",
            "--no-map-gw",
        ])
        .arg("--socket")
        .arg(&sock)
        .args([
            "--address",
            GUEST_ADDR,
            "--netmask",
            "24",
            "--gateway",
            GATEWAY,
        ])
        .args([
            "--dns-forward",
            DNS,
            "--tcp-ports",
            "none",
            "--udp-ports",
            "none",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            err(
                ErrorCode::HostSetup,
                format!("start {}: {e}", bin.display()),
            )
        })?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while !sock.exists() {
        if Instant::now() > deadline || matches!(child.try_wait(), Ok(Some(_))) {
            let _ = child.kill().await;
            return Err(err(ErrorCode::HostSetup, "passt did not start")
                .hint("run `passt --vhost-user --socket /tmp/x.sock -f` to see why"));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tracing::warn!(
        "full network access via passt ({}): not filtered by the pocket proxy",
        sock.display()
    );
    let task = tokio::spawn(async move {
        let _ = child.wait().await;
    });
    Ok((sock, task))
}
