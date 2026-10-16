//! Cloud Hypervisor driver (D3): process launch, REST API over the API socket.

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::{
    BackendCaps, BoxFut, DiskSpec, DiskTransport, HostFingerprint, SnapshotRef, StopMode, VmHandle,
    VmSpec, VmmBackend, VmmError, cgroup, process,
};

#[derive(Debug, Clone)]
pub struct Disk {
    pub path: PathBuf,
    pub read_only: bool,
}

/// Cold boot of one VM. Disk order defines guest order: `/dev/vda`, `/dev/vdb`, ...;
/// pmem devices appear as `/dev/pmem0`, ...
#[derive(Debug, Clone)]
pub struct LaunchSpec {
    pub binary: PathBuf,
    pub kernel: PathBuf,
    pub cmdline: String,
    pub vcpus: u8,
    pub memory_mib: u32,
    pub disks: Vec<Disk>,
    pub pmem: Vec<PathBuf>,
    pub vsock_cid: u32,
    pub vsock_uds: PathBuf,
    pub api_socket: PathBuf,
    /// Guest serial console goes here (and `console=ttyS0` is added) when set.
    pub serial_log: Option<PathBuf>,
    /// virtio-balloon with free page reporting (starts deflated).
    pub balloon: bool,
    /// virtio-fs devices `(tag, vhost-user socket)`; guest memory is then shared.
    pub fs: Vec<(String, PathBuf)>,
}

impl LaunchSpec {
    pub fn command(&self) -> Command {
        let mut cmdline = self.cmdline.clone();
        if self.serial_log.is_some() {
            cmdline.push_str(" console=ttyS0");
        }
        let mut c = Command::new(&self.binary);
        c.arg("--api-socket")
            .arg(&self.api_socket)
            .arg("--kernel")
            .arg(&self.kernel)
            .arg("--cmdline")
            .arg(cmdline)
            .arg("--cpus")
            .arg(format!("boot={}", self.vcpus))
            .arg("--memory")
            .arg(if self.fs.is_empty() {
                format!("size={}M", self.memory_mib)
            } else {
                format!("size={}M,shared=on", self.memory_mib)
            });
        for (tag, sock) in &self.fs {
            c.arg("--fs")
                .arg(format!("tag={tag},socket={}", sock.display()));
        }
        if !self.disks.is_empty() {
            c.arg("--disk");
            for d in &self.disks {
                c.arg(format!(
                    "path={},readonly={},image_type=raw",
                    d.path.display(),
                    if d.read_only { "on" } else { "off" }
                ));
            }
        }
        if !self.pmem.is_empty() {
            c.arg("--pmem");
            for p in &self.pmem {
                c.arg(format!("file={},discard_writes=on", p.display()));
            }
        }
        c.arg("--vsock").arg(format!(
            "cid={},socket={}",
            self.vsock_cid,
            self.vsock_uds.display()
        ));
        c.arg("--rng").arg("src=/dev/urandom");
        if self.balloon {
            c.arg("--balloon")
                .arg("size=0,deflate_on_oom=on,free_page_reporting=on");
        }
        match &self.serial_log {
            Some(p) => c.arg("--serial").arg(format!("file={}", p.display())),
            None => c.arg("--serial").arg("off"),
        };
        c.arg("--console").arg("off");
        c
    }
}

const NAME: &str = "cloud-hypervisor";
const API_READY_TIMEOUT: Duration = Duration::from_secs(5);

/// Cloud Hypervisor driver (D3).
pub struct CloudHypervisor {
    binary: PathBuf,
    version: String,
}

impl CloudHypervisor {
    /// Probes `binary --version` (`cloud-hypervisor v54.0.0…`); a missing binary gives
    /// version `missing` and fails at `create` (so `pocket doctor` can still report it).
    pub fn new(binary: PathBuf) -> Result<Self, VmmError> {
        let version = Command::new(&binary)
            .arg("--version")
            .output()
            .ok()
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .split_whitespace()
                    .nth(1)
                    .map(|v| v.trim_start_matches('v').to_string())
            })
            .unwrap_or_else(|| "missing".into());
        Ok(CloudHypervisor { binary, version })
    }

    fn major(&self) -> u32 {
        self.version
            .split('.')
            .next()
            .and_then(|m| m.parse().ok())
            .unwrap_or(0)
    }

    fn launch_spec(&self, spec: &VmSpec) -> LaunchSpec {
        let mut disks = vec![];
        let mut pmem = vec![];
        for d in &spec.disks {
            match d.transport {
                DiskTransport::Blk => disks.push(Disk {
                    path: d.path.clone(),
                    read_only: d.read_only,
                }),
                DiskTransport::Pmem { .. } => pmem.push(d.path.clone()),
            }
        }
        LaunchSpec {
            binary: self.binary.clone(),
            kernel: spec.kernel.clone(),
            cmdline: spec.cmdline.clone(),
            vcpus: spec.vcpus,
            memory_mib: spec.memory_mib,
            disks,
            pmem,
            vsock_cid: spec.vsock_cid,
            vsock_uds: spec.runtime_dir.join("vsock.sock"),
            api_socket: spec.runtime_dir.join("api.sock"),
            serial_log: spec.serial_log.clone(),
            balloon: true,
            fs: spec.shared_fs.clone(),
        }
    }

    async fn wait_api(&self, h: &VmHandle, log: &Path) -> Result<(), VmmError> {
        let deadline = Instant::now() + API_READY_TIMEOUT;
        loop {
            if !process::alive(h.pid, h.start_time) {
                let tail = std::fs::read_to_string(log).unwrap_or_default();
                let tail: String = tail.lines().rev().take(20).collect::<Vec<_>>().join("\n");
                return Err(VmmError::Io {
                    what: format!("{NAME} exited during start (log: {})", log.display()),
                    source: std::io::Error::other(tail),
                });
            }
            if api(&h.api_socket, "GET", "vmm.ping", None).await.is_ok() {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(VmmError::Io {
                    what: format!("{NAME} API did not come up"),
                    source: std::io::ErrorKind::TimedOut.into(),
                });
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    async fn kill(&self, vm: &VmHandle) -> Result<(), VmmError> {
        process::kill(vm.pid, vm.start_time, libc::SIGKILL);
        process::wait_exit(vm.pid, vm.start_time)
            .await
            .map_err(VmmError::io("wait for VMM exit"))?;
        if let Some(u) = &vm.cgroup_unit {
            cgroup::stop_scope(u);
        }
        Ok(())
    }
}

impl VmmBackend for CloudHypervisor {
    fn name(&self) -> &'static str {
        NAME
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn capabilities(&self) -> BackendCaps {
        BackendCaps {
            pmem_dax: true,
            disk_hotplug: true,
            // copyonwrite restore landed after v53 (D3).
            lazy_restore: self.major() >= 54,
            free_page_reporting: true,
            rebind_disk_on_restore: true,
        }
    }

    fn create<'a>(&'a self, spec: &'a VmSpec) -> BoxFut<'a, VmHandle> {
        Box::pin(async move {
            let ls = self.launch_spec(spec);
            std::fs::create_dir_all(&spec.runtime_dir).map_err(VmmError::io(format!(
                "create {}",
                spec.runtime_dir.display()
            )))?;
            for s in [&ls.api_socket, &ls.vsock_uds] {
                let _ = std::fs::remove_file(s);
            }
            let inner = ls.command();
            let (mut cmd, unit) = match &spec.cgroup {
                Some(cg) if cgroup::systemd_scopes_available() => {
                    (cgroup::wrap(cg, &inner), Some(cg.unit.clone()))
                }
                _ => {
                    let mut c = Command::new(inner.get_program());
                    c.args(inner.get_args());
                    (c, None)
                }
            };
            let log = std::fs::File::create(&spec.log_path)
                .map_err(VmmError::io(format!("create {}", spec.log_path.display())))?;
            let log2 = log.try_clone().map_err(VmmError::io("dup log"))?;
            // Own process group: a Ctrl-C aimed at a foreground daemon must not reach VMs.
            let child = cmd
                .stdin(Stdio::null())
                .stdout(log)
                .stderr(log2)
                .process_group(0)
                .spawn()
                .map_err(|source| VmmError::Spawn {
                    binary: cmd.get_program().into(),
                    source,
                })?;
            let pid = child.id();
            drop(child); // reaped by `wait_exit`
            let start_time = process::start_time(pid).unwrap_or(0);
            let h = VmHandle {
                id: spec.id.clone(),
                backend: NAME.into(),
                pid,
                start_time,
                api_socket: ls.api_socket,
                vsock_uds: ls.vsock_uds,
                cgroup_unit: unit,
            };
            if let Err(e) = self.wait_api(&h, &spec.log_path).await {
                let _ = self.kill(&h).await;
                return Err(e);
            }
            Ok(h)
        })
    }

    fn restore<'a>(&'a self, _snap: &'a SnapshotRef, _spec: &'a VmSpec) -> BoxFut<'a, VmHandle> {
        // Template restore is the M9 start path.
        Box::pin(async { Err(VmmError::Unsupported("restore")) })
    }

    fn pause<'a>(&'a self, vm: &'a VmHandle) -> BoxFut<'a, ()> {
        Box::pin(async move { api_ok(&vm.api_socket, "vm.pause", None).await })
    }

    fn resume<'a>(&'a self, vm: &'a VmHandle) -> BoxFut<'a, ()> {
        Box::pin(async move { api_ok(&vm.api_socket, "vm.resume", None).await })
    }

    fn snapshot<'a>(&'a self, vm: &'a VmHandle, dest: &'a Path) -> BoxFut<'a, SnapshotRef> {
        Box::pin(async move {
            std::fs::create_dir_all(dest)
                .map_err(VmmError::io(format!("create {}", dest.display())))?;
            let body =
                serde_json::json!({ "destination_url": format!("file://{}", dest.display()) });
            api_ok(&vm.api_socket, "vm.snapshot", Some(&body.to_string())).await?;
            Ok(SnapshotRef {
                dir: dest.to_path_buf(),
                backend: NAME.into(),
                host_fingerprint: host_fingerprint(&self.version),
                disks: vec![],
            })
        })
    }

    fn hotplug_disk<'a>(&'a self, vm: &'a VmHandle, disk: &'a DiskSpec) -> BoxFut<'a, ()> {
        Box::pin(async move {
            let body = match disk.transport {
                DiskTransport::Blk => serde_json::json!({
                    "path": disk.path, "readonly": disk.read_only
                }),
                DiskTransport::Pmem { .. } => return Err(VmmError::Unsupported("pmem hotplug")),
            };
            api_ok(&vm.api_socket, "vm.add-disk", Some(&body.to_string())).await
        })
    }

    fn set_balloon<'a>(&'a self, vm: &'a VmHandle, target_bytes: u64) -> BoxFut<'a, ()> {
        Box::pin(async move {
            let body = serde_json::json!({ "desired_balloon": target_bytes });
            api_ok(&vm.api_socket, "vm.resize", Some(&body.to_string())).await
        })
    }

    fn stop<'a>(&'a self, vm: &'a VmHandle, mode: StopMode) -> BoxFut<'a, ()> {
        Box::pin(async move {
            if let StopMode::Graceful { timeout_ms } = mode {
                let wait = process::wait_exit(vm.pid, vm.start_time);
                if tokio::time::timeout(Duration::from_millis(timeout_ms.into()), wait)
                    .await
                    .is_ok()
                {
                    if let Some(u) = &vm.cgroup_unit {
                        cgroup::stop_scope(u);
                    }
                    return Ok(());
                }
                let _ = api(&vm.api_socket, "PUT", "vmm.shutdown", None).await;
                let wait = process::wait_exit(vm.pid, vm.start_time);
                if tokio::time::timeout(Duration::from_secs(1), wait)
                    .await
                    .is_ok()
                {
                    if let Some(u) = &vm.cgroup_unit {
                        cgroup::stop_scope(u);
                    }
                    return Ok(());
                }
            }
            self.kill(vm).await
        })
    }

    fn adopt<'a>(&'a self, vm: &'a VmHandle) -> BoxFut<'a, ()> {
        Box::pin(async move {
            if !process::alive(vm.pid, vm.start_time)
                || !process::exe_name(vm.pid).is_some_and(|n| n.starts_with(NAME))
            {
                return Err(VmmError::NotRunning { pid: vm.pid });
            }
            api_ok(&vm.api_socket, "vmm.ping", None).await
        })
    }

    fn wait_exit<'a>(&'a self, vm: &'a VmHandle) -> BoxFut<'a, ()> {
        Box::pin(async move {
            process::wait_exit(vm.pid, vm.start_time)
                .await
                .map_err(VmmError::io("wait for VMM exit"))
        })
    }

    fn vsock_uds(&self, vm: &VmHandle) -> PathBuf {
        vm.vsock_uds.clone()
    }
}

pub fn host_fingerprint(vmm_version: &str) -> HostFingerprint {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let field = |k: &str| {
        cpuinfo
            .lines()
            .find(|l| l.starts_with(k))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default()
    };
    let flags = field("flags");
    let mut h: u64 = 0xcbf29ce484222325;
    for b in flags.bytes() {
        h = (h ^ b as u64).wrapping_mul(0x100000001b3);
    }
    HostFingerprint {
        cpu_model: field("model name"),
        cpu_flags_hash: format!("{h:016x}"),
        host_kernel: std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_default()
            .trim()
            .to_string(),
        vmm_version: format!("{NAME} {vmm_version}"),
    }
}

async fn api_ok(sock: &Path, call: &str, body: Option<&str>) -> Result<(), VmmError> {
    let method = if call == "vmm.ping" { "GET" } else { "PUT" };
    let (status, text) = api(sock, method, call, body).await?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(VmmError::Api {
            call: call.into(),
            status,
            body: text,
        })
    }
}

/// Minimal HTTP/1.1 client for the VMM API socket.
async fn api(
    sock: &Path,
    method: &str,
    call: &str,
    body: Option<&str>,
) -> Result<(u16, String), VmmError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let io = VmmError::io(format!("{NAME} API {call}"));
    let run = async {
        let mut s = tokio::net::UnixStream::connect(sock).await?;
        let body = body.unwrap_or("");
        let mut req = format!(
            "{method} /api/v1/{call} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n"
        );
        if !body.is_empty() {
            req.push_str("Content-Type: application/json\r\n");
        }
        req.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
        s.write_all(req.as_bytes()).await?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let (head_end, content_len) = loop {
            let n = s.read(&mut chunk).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "API closed before a full response",
                ));
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() > 1 << 20 {
                return Err(std::io::Error::other("API response too large"));
            }
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..i]).to_ascii_lowercase();
                let len = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                break (i + 4, len);
            }
        };
        while buf.len() < head_end + content_len {
            let n = s.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let head = String::from_utf8_lossy(&buf[..head_end]);
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let end = buf.len().min(head_end + content_len);
        Ok((
            status,
            String::from_utf8_lossy(&buf[head_end..end]).into_owned(),
        ))
    };
    tokio::time::timeout(Duration::from_secs(10), run)
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))
        .and_then(|r| r)
        .map_err(io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_lists_devices_in_order() {
        let spec = LaunchSpec {
            binary: "/ch".into(),
            kernel: "/k".into(),
            cmdline: "quiet".into(),
            vcpus: 2,
            memory_mib: 256,
            disks: vec![
                Disk {
                    path: "/sys.erofs".into(),
                    read_only: true,
                },
                Disk {
                    path: "/disk.raw".into(),
                    read_only: false,
                },
            ],
            pmem: vec!["/base.erofs".into()],
            vsock_cid: 3,
            vsock_uds: "/v.sock".into(),
            api_socket: "/api.sock".into(),
            serial_log: None,
            balloon: true,
            fs: vec![],
        };
        let args: Vec<String> = spec
            .command()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let disk = args.iter().position(|a| a == "--disk").unwrap();
        assert_eq!(args[disk + 1], "path=/sys.erofs,readonly=on,image_type=raw");
        assert_eq!(args[disk + 2], "path=/disk.raw,readonly=off,image_type=raw");
        assert!(args.contains(&"file=/base.erofs,discard_writes=on".to_string()));
        assert!(args.contains(&"cid=3,socket=/v.sock".to_string()));
        assert!(args.contains(&"quiet".to_string()));
        assert!(args.contains(&"size=0,deflate_on_oom=on,free_page_reporting=on".to_string()));
    }
}
