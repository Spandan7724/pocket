//! VMM backends (CONTRACTS.md §1). The only crate that knows which VMM runs a pocket.

pub mod cgroup;
pub mod cloud_hypervisor;
pub mod process;
pub mod sparse;
pub mod vsock;

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use serde::{Deserialize, Serialize};

pub use cgroup::CgroupSpec;

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = Result<T, VmmError>> + Send + 'a>>;

#[derive(Debug, thiserror::Error)]
pub enum VmmError {
    #[error("{0} is not supported by this backend")]
    Unsupported(&'static str),
    #[error("could not start the VMM ({binary}): {source}")]
    Spawn {
        binary: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("VMM API {call} failed: HTTP {status}: {body}")]
    Api {
        call: String,
        status: u16,
        body: String,
    },
    #[error("VMM process {pid} is not running")]
    NotRunning { pid: u32 },
    #[error("{what}: {source}")]
    Io {
        what: String,
        #[source]
        source: std::io::Error,
    },
}

impl VmmError {
    pub fn io(what: impl Into<String>) -> impl FnOnce(std::io::Error) -> VmmError {
        let what = what.into();
        move |source| VmmError::Io { what, source }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendCaps {
    pub pmem_dax: bool,
    pub disk_hotplug: bool,
    /// Memory is mapped on demand, not copied, on restore.
    pub lazy_restore: bool,
    pub free_page_reporting: bool,
    /// Restore can point disks at new backing files.
    pub rebind_disk_on_restore: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiskRole {
    System,
    Base,
    Pocket,
    Extra(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiskTransport {
    Blk,
    Pmem { dax: bool },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskSpec {
    pub role: DiskRole,
    pub path: PathBuf,
    pub read_only: bool,
    pub transport: DiskTransport,
}

/// Guest device node of each disk, in order: virtio-blk disks enumerate as `/dev/vda`,
/// `/dev/vdb`, … and pmem devices as `/dev/pmem0`, … in the order given.
pub fn guest_devices(disks: &[DiskSpec]) -> Vec<String> {
    let (mut blk, mut pmem) = (0u8, 0u32);
    disks
        .iter()
        .map(|d| match d.transport {
            DiskTransport::Blk => {
                let n = format!("/dev/vd{}", (b'a' + blk) as char);
                blk += 1;
                n
            }
            DiskTransport::Pmem { .. } => {
                let n = format!("/dev/pmem{pmem}");
                pmem += 1;
                n
            }
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct VmSpec {
    pub id: String,
    pub vcpus: u8,
    pub memory_mib: u32,
    pub kernel: PathBuf,
    pub cmdline: String,
    /// Order defines guest device order: system, base, pocket.
    pub disks: Vec<DiskSpec>,
    pub vsock_cid: u32,
    /// The VMM process is started inside this scope when set.
    pub cgroup: Option<CgroupSpec>,
    /// Holds the API and vsock sockets; must be short (UDS paths ≤ 108 bytes).
    pub runtime_dir: PathBuf,
    pub log_path: PathBuf,
    /// Guest serial console is written here when set (debugging only; slow).
    pub serial_log: Option<PathBuf>,
    /// virtio-fs shares `(tag, vhost-user socket)`, served by a virtiofsd the caller runs.
    pub shared_fs: Vec<(String, PathBuf)>,
    /// A virtio-net NIC through this vhost-user socket (passt, `--net full`); none by default.
    pub net_vhost: Option<PathBuf>,
}

/// Everything needed to find a running VM again, also after a daemon restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmHandle {
    pub id: String,
    pub backend: String,
    pub pid: u32,
    /// `/proc/<pid>/stat` start time; guards against pid reuse when re-adopting.
    pub start_time: u64,
    pub api_socket: PathBuf,
    pub vsock_uds: PathBuf,
    pub cgroup_unit: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopMode {
    Graceful { timeout_ms: u32 },
    Kill,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostFingerprint {
    pub cpu_model: String,
    pub cpu_flags_hash: String,
    pub host_kernel: String,
    pub vmm_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRef {
    pub dir: PathBuf,
    /// Snapshots are never restored by another backend.
    pub backend: String,
    pub host_fingerprint: HostFingerprint,
    pub disks: Vec<DiskSpec>,
}

/// Default backend's binary inside an assets directory (`<assets>/bin/…`).
pub fn default_binary(assets: &Path) -> PathBuf {
    assets.join("bin").join("cloud-hypervisor")
}

/// The default backend (D3), using the VMM binary at `binary`.
pub fn default_backend(binary: PathBuf) -> Result<std::sync::Arc<dyn VmmBackend>, VmmError> {
    Ok(std::sync::Arc::new(cloud_hypervisor::CloudHypervisor::new(
        binary,
    )?))
}

pub trait VmmBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn version(&self) -> &str;
    fn capabilities(&self) -> BackendCaps;
    /// What a snapshot taken now is tied to (CPU, host kernel, VMM version).
    fn host_fingerprint(&self) -> HostFingerprint;

    /// Cold boot.
    fn create<'a>(&'a self, spec: &'a VmSpec) -> BoxFut<'a, VmHandle>;
    fn restore<'a>(&'a self, snap: &'a SnapshotRef, spec: &'a VmSpec) -> BoxFut<'a, VmHandle>;
    fn pause<'a>(&'a self, vm: &'a VmHandle) -> BoxFut<'a, ()>;
    fn resume<'a>(&'a self, vm: &'a VmHandle) -> BoxFut<'a, ()>;
    /// The VM must be paused.
    fn snapshot<'a>(&'a self, vm: &'a VmHandle, dest: &'a Path) -> BoxFut<'a, SnapshotRef>;
    fn hotplug_disk<'a>(&'a self, vm: &'a VmHandle, disk: &'a DiskSpec) -> BoxFut<'a, ()>;
    fn set_balloon<'a>(&'a self, vm: &'a VmHandle, target_bytes: u64) -> BoxFut<'a, ()>;
    /// Graceful: wait for the guest to power off (the caller asks it to first), then ask
    /// the VMM, then kill. The VMM process is gone when this returns `Ok`.
    fn stop<'a>(&'a self, vm: &'a VmHandle, mode: StopMode) -> BoxFut<'a, ()>;
    /// Checks that a VM recorded earlier (e.g. before a daemon restart) is still this
    /// backend's live VMM and answers its API.
    fn adopt<'a>(&'a self, vm: &'a VmHandle) -> BoxFut<'a, ()>;
    /// Resolves when the VMM process has exited.
    fn wait_exit<'a>(&'a self, vm: &'a VmHandle) -> BoxFut<'a, ()>;
    /// Hybrid vsock UDS of the VM.
    fn vsock_uds(&self, vm: &VmHandle) -> PathBuf;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_names_follow_transport_order() {
        let d = |transport| DiskSpec {
            role: DiskRole::Base,
            path: "/x".into(),
            read_only: true,
            transport,
        };
        let disks = [
            d(DiskTransport::Blk),
            d(DiskTransport::Pmem { dax: true }),
            d(DiskTransport::Blk),
        ];
        assert_eq!(
            guest_devices(&disks),
            ["/dev/vda", "/dev/pmem0", "/dev/vdb"]
        );
    }
}
