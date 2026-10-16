//! Shared helpers for the KVM integration tests.
//!
//! Tests call [`kvm_or_skip`] first: without usable `/dev/kvm` (or without built assets)
//! they print why and return, unless `POCKET_KVM_TESTS=require`, which turns the skip into
//! a failure.

pub mod cli;
pub mod fake;
pub mod guest;
pub mod pty;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use pocket_vmm::cloud_hypervisor::{Disk, LaunchSpec};

pub const BOOT_ARGS: &str = "root=/dev/vda ro rootfstype=erofs init=/pocket-init \
    reboot=k panic=-1 8250.nr_uarts=1 i8042.noaux i8042.nomux i8042.dumbkbd quiet \
    rcupdate.rcu_expedited=1";

pub struct Assets {
    pub vmm: PathBuf,
    pub kernel: PathBuf,
    pub system: PathBuf,
    pub base: PathBuf,
}

fn required() -> bool {
    std::env::var("POCKET_KVM_TESTS").as_deref() == Ok("require")
}

fn skip(why: &str) -> Option<Assets> {
    if required() {
        panic!("POCKET_KVM_TESTS=require but {why}");
    }
    eprintln!("skipping KVM test: {why} (set POCKET_KVM_TESTS=require to fail instead)");
    None
}

/// Returns the built assets, or `None` (after printing why) when the test must be skipped.
pub fn kvm_or_skip() -> Option<Assets> {
    if fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_err()
    {
        return skip("/dev/kvm is missing or not read-writable");
    }
    let dir = std::env::var_os("POCKET_ASSETS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/pocket"));
    let a = Assets {
        vmm: dir.join("bin/cloud-hypervisor"),
        kernel: dir.join("kernel/vmlinux"),
        system: dir.join("system.erofs"),
        base: dir.join("test-base.erofs"),
    };
    for p in [&a.vmm, &a.kernel, &a.system, &a.base] {
        if !p.exists() {
            return skip(&format!(
                "{} is missing; run `cargo xtask assets`",
                p.display()
            ));
        }
    }
    Some(a)
}

/// A fresh directory with a short path (UDS paths are limited to 108 bytes).
pub fn scratch_dir(tag: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let d = std::env::temp_dir().join(format!(
        "pkt-{}-{}-{tag}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// Sparse, freshly formatted ext4 image (stand-in for the M3 pocket disk).
pub fn make_ext4(path: &Path, size_mib: u64) {
    let f = fs::File::create(path).unwrap();
    f.set_len(size_mib << 20).unwrap();
    let st = Command::new("mkfs.ext4")
        .args(["-q", "-F", "-E", "lazy_itable_init=1,lazy_journal_init=1"])
        .arg(path)
        .status()
        .expect("mkfs.ext4 (e2fsprogs) is required for the integration tests");
    assert!(st.success(), "mkfs.ext4 failed");
}

pub struct VmOpts {
    pub memory_mib: u32,
    pub vcpus: u8,
    /// Root is always the system image; the base image goes on pmem unless `base_blk`.
    pub base_blk: bool,
    pub pocket_disk: Option<PathBuf>,
    pub extra_cmdline: String,
    pub serial: bool,
}

impl Default for VmOpts {
    fn default() -> Self {
        VmOpts {
            memory_mib: 512,
            vcpus: 2,
            base_blk: false,
            pocket_disk: None,
            extra_cmdline: String::new(),
            serial: true,
        }
    }
}

pub struct TestVm {
    pub dir: PathBuf,
    pub vsock_uds: PathBuf,
    pub serial_log: PathBuf,
    pub started: Instant,
    child: Option<Child>,
}

impl TestVm {
    pub fn boot(a: &Assets, tag: &str, o: VmOpts) -> TestVm {
        let dir = scratch_dir(tag);
        let mut disks = vec![Disk {
            path: a.system.clone(),
            read_only: true,
        }];
        let mut pmem = vec![];
        let mut cmdline = BOOT_ARGS.to_string();
        if o.base_blk {
            disks.push(Disk {
                path: a.base.clone(),
                read_only: true,
            });
            cmdline.push_str(" pocket.base=/dev/vdb");
        } else {
            pmem.push(a.base.clone());
            cmdline.push_str(" pocket.base=/dev/pmem0");
        }
        if let Some(d) = &o.pocket_disk {
            let dev = if o.base_blk { "/dev/vdc" } else { "/dev/vdb" };
            disks.push(Disk {
                path: d.clone(),
                read_only: false,
            });
            cmdline.push_str(&format!(" pocket.disk={dev}"));
        }
        if o.serial {
            cmdline.push_str(" loglevel=7");
        }
        if !o.extra_cmdline.is_empty() {
            cmdline.push(' ');
            cmdline.push_str(&o.extra_cmdline);
        }
        let spec = LaunchSpec {
            binary: a.vmm.clone(),
            kernel: a.kernel.clone(),
            cmdline,
            vcpus: o.vcpus,
            memory_mib: o.memory_mib,
            disks,
            pmem,
            vsock_cid: 3,
            vsock_uds: dir.join("vsock.sock"),
            api_socket: dir.join("api.sock"),
            serial_log: o.serial.then(|| dir.join("serial.log")),
            balloon: false,
            fs: vec![],
        };
        let log = fs::File::create(dir.join("vmm.log")).unwrap();
        let started = Instant::now();
        let child = spec
            .command()
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn cloud-hypervisor");
        TestVm {
            vsock_uds: spec.vsock_uds,
            serial_log: dir.join("serial.log"),
            dir,
            started,
            child: Some(child),
        }
    }

    pub fn wait_exit(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;
        let child = self.child.as_mut()?;
        loop {
            if let Some(st) = child.try_wait().unwrap() {
                return Some(st);
            }
            if Instant::now() > deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn logs(&self) -> String {
        format!(
            "--- serial.log\n{}\n--- vmm.log\n{}",
            fs::read_to_string(&self.serial_log).unwrap_or_default(),
            fs::read_to_string(self.dir.join("vmm.log")).unwrap_or_default()
        )
    }
}

impl Drop for TestVm {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        if std::thread::panicking() {
            eprintln!("VM dir kept: {}\n{}", self.dir.display(), self.logs());
        } else {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
}
