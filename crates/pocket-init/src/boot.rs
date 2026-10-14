//! Boot: basic mounts, base image + pocket disk, overlay root, `pivot_root`, hostname,
//! RNG seed. Runs on the read-only system image; afterwards it is reachable at
//! `/run/pocket/system`.

use std::fs;
use std::io::{self, Read};

use crate::log;
use crate::sys::{self, bind_mount, mount, move_mount, pivot_root};

const NOSUID_NODEV_NOEXEC: libc::c_ulong = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;

pub const BASE: &str = "/run/pocket/base";
pub const DISK: &str = "/run/pocket/disk";

pub struct Cmdline {
    pub base: Option<String>,
    pub disk: Option<String>,
    pub hostname: String,
}

fn parse_cmdline(s: &str) -> Cmdline {
    let mut c = Cmdline {
        base: None,
        disk: None,
        hostname: "pocket".into(),
    };
    for kv in s.split_whitespace() {
        match kv.split_once('=') {
            Some(("pocket.base", v)) => c.base = Some(v.into()),
            Some(("pocket.disk", v)) => c.disk = Some(v.into()),
            Some(("pocket.hostname", v)) if pocket_proto::guest::valid_hostname(v) => {
                c.hostname = v.into()
            }
            _ => {}
        }
    }
    c
}

fn mkdirs(paths: &[&str]) -> io::Result<()> {
    for p in paths {
        fs::create_dir_all(p).map_err(|e| io::Error::new(e.kind(), format!("mkdir {p}: {e}")))?;
    }
    Ok(())
}

fn early_mounts() -> io::Result<()> {
    mount("proc", "/proc", "proc", NOSUID_NODEV_NOEXEC, None)?;
    mount("sysfs", "/sys", "sysfs", NOSUID_NODEV_NOEXEC, None)?;
    // CONFIG_DEVTMPFS_MOUNT may already have mounted it.
    match sys::mount_raw(
        "devtmpfs",
        "/dev",
        "devtmpfs",
        libc::MS_NOSUID,
        Some("mode=0755"),
    ) {
        Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {}
        r => r.map_err(|e| io::Error::new(e.kind(), format!("mount devtmpfs on /dev: {e}")))?,
    }
    mount(
        "tmpfs",
        "/run",
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NODEV,
        Some("mode=0755"),
    )?;
    mkdirs(&[
        "/dev/pts",
        "/dev/shm",
        "/run/pocket/base",
        "/run/pocket/disk",
        "/run/pocket/system",
    ])?;
    mount(
        "devpts",
        "/dev/pts",
        "devpts",
        libc::MS_NOSUID | libc::MS_NOEXEC,
        Some("mode=0620,ptmxmode=0666"),
    )?;
    mount(
        "tmpfs",
        "/dev/shm",
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NODEV,
        Some("mode=1777"),
    )?;
    mount(
        "cgroup2",
        "/sys/fs/cgroup",
        "cgroup2",
        NOSUID_NODEV_NOEXEC,
        None,
    )?;
    Ok(())
}

fn seed_from_hwrng() {
    let mut seed = [0u8; 64];
    match fs::File::open("/dev/hwrng").and_then(|mut f| f.read_exact(&mut seed)) {
        Ok(()) => match sys::add_entropy(&seed) {
            Ok(()) => log!("rng seeded with 64 bytes from virtio-rng"),
            Err(e) => log!("rng seed failed: {e}"),
        },
        Err(e) => log!("no hardware rng ({e}); relying on host seed via Configure"),
    }
}

/// Boot phases with the guest `CLOCK_BOOTTIME` at their end, for the ready log line.
#[derive(Default)]
pub struct Phases(Vec<(&'static str, u64)>);

impl Phases {
    fn mark(&mut self, name: &'static str) {
        self.0.push((name, sys::boottime_ns()));
    }

    pub fn summary(&self, start: u64) -> String {
        let mut prev = start;
        let mut out = Vec::new();
        for (name, t) in &self.0 {
            out.push(format!("{name} {:.2}", (t - prev) as f64 / 1e6));
            prev = *t;
        }
        out.join(", ") + " ms"
    }
}

pub fn boot(p: &mut Phases) -> io::Result<Cmdline> {
    p.mark("start");
    early_mounts()?;
    p.mark("early-mounts");
    let c = parse_cmdline(&fs::read_to_string("/proc/cmdline")?);

    let base = c
        .base
        .as_deref()
        .ok_or_else(|| io::Error::other("pocket.base= missing from the kernel command line"))?;
    let dax = base.starts_with("/dev/pmem").then_some("dax=always");
    mount(base, BASE, "erofs", libc::MS_RDONLY | libc::MS_NODEV, dax)?;
    p.mark("base");

    match c.disk.as_deref() {
        Some(dev) => mount(dev, DISK, "ext4", libc::MS_NOATIME | libc::MS_NODEV, None)?,
        None => {
            log!("no pocket.disk=; changes live in memory only");
            mount("tmpfs", DISK, "tmpfs", libc::MS_NODEV, Some("mode=0755"))?
        }
    }
    p.mark("disk");
    let upper = format!("{DISK}/root/upper");
    let work = format!("{DISK}/root/work");
    mkdirs(&[
        &upper,
        &work,
        &format!("{DISK}/work"),
        &format!("{DISK}/home"),
    ])?;
    mount(
        "overlay",
        "/newroot",
        "overlay",
        0,
        Some(&format!("lowerdir={BASE},upperdir={upper},workdir={work}")),
    )?;
    mkdirs(&[
        "/newroot/proc",
        "/newroot/sys",
        "/newroot/dev",
        "/newroot/run",
        "/newroot/work",
        "/newroot/home",
        "/newroot/tmp",
    ])?;
    for m in ["/proc", "/sys", "/dev", "/run"] {
        move_mount(m, &format!("/newroot{m}"))?;
    }
    std::env::set_current_dir("/newroot")?;
    pivot_root("/newroot", "/newroot/run/pocket/system")
        .map_err(|e| io::Error::new(e.kind(), format!("pivot_root: {e}")))?;
    std::env::set_current_dir("/")?;

    bind_mount(&format!("{DISK}/work"), "/work")?;
    bind_mount(&format!("{DISK}/home"), "/home")?;
    mount(
        "tmpfs",
        "/tmp",
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NODEV,
        Some("mode=1777"),
    )?;

    p.mark("overlay+pivot");
    sys::sethostname(&c.hostname)?;
    if let Err(e) = sys::loopback_up() {
        log!("lo up: {e}");
    }
    crate::users::first_boot_setup();
    p.mark("lo+users");
    seed_from_hwrng();
    p.mark("rng");
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmdline_keys() {
        let c = parse_cmdline(
            "quiet pocket.base=/dev/pmem0 pocket.disk=/dev/vdb pocket.hostname=web-1 x=y",
        );
        assert_eq!(c.base.as_deref(), Some("/dev/pmem0"));
        assert_eq!(c.disk.as_deref(), Some("/dev/vdb"));
        assert_eq!(c.hostname, "web-1");
        assert_eq!(
            parse_cmdline("pocket.hostname=bad_name!").hostname,
            "pocket"
        );
    }
}
