//! Host checks for `pocket doctor`; each failure carries a fix.

use std::process::{Command, Stdio};

use pocket_proto::rpc::Check;

use crate::daemon::Daemon;
use crate::presets;

fn check(name: &str, ok: bool, detail: impl Into<String>, fix: Option<&str>) -> Check {
    Check {
        name: name.into(),
        ok,
        warn: false,
        detail: detail.into(),
        fix: if ok { None } else { fix.map(String::from) },
    }
}

fn warn(name: &str, detail: impl Into<String>, fix: &str) -> Check {
    Check {
        name: name.into(),
        ok: true,
        warn: true,
        detail: detail.into(),
        fix: Some(fix.into()),
    }
}

fn tool_version(cmd: &str, arg: &str) -> Option<String> {
    let o = Command::new(cmd)
        .arg(arg)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(if o.stdout.is_empty() {
        &o.stderr
    } else {
        &o.stdout
    })
    .into_owned();
    text.lines().next().map(|l| l.trim().to_string())
}

pub fn checks(d: &Daemon) -> Vec<Check> {
    let mut v = vec![];
    let dev = std::env::var("POCKET_DOCTOR_KVM").unwrap_or_else(|_| "/dev/kvm".into());
    let kvm = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&dev);
    v.push(check(
        "kvm",
        kvm.is_ok(),
        match &kvm {
            Ok(_) => format!("{dev} is read-writable"),
            Err(e) => format!("{dev}: {e}"),
        },
        Some("enable virtualization in the firmware, load kvm_intel/kvm_amd, and add yourself to the kvm group: `sudo usermod -aG kvm $USER` (log in again)"),
    ));

    let scopes = pocket_vmm::cgroup::systemd_scopes_available();
    let ctrl = pocket_vmm::cgroup::delegated_controllers().unwrap_or_default();
    let have = |c: &str| ctrl.split_whitespace().any(|x| x == c);
    let delegated = have("cpu") && have("memory") && have("pids");
    v.push(check(
        "cgroups",
        scopes && delegated,
        format!(
            "systemd user scopes: {}; delegated controllers: {}",
            if scopes { "yes" } else { "no" },
            if ctrl.is_empty() { "none" } else { &ctrl }
        ),
        Some("pocket needs cgroup v2 with cpu, memory and pids delegated to your user manager: create /etc/systemd/system/user@.service.d/delegate.conf with `[Service]` / `Delegate=cpu memory pids`, then `sudo systemctl daemon-reload` and log in again"),
    ));

    let dir = d.paths.data.join(format!(".doctor-{}", std::process::id()));
    let reflink = (|| {
        std::fs::create_dir_all(&dir).ok()?;
        let a = dir.join("a");
        std::fs::write(&a, vec![1u8; 65536]).ok()?;
        let mode = pocket_image::disk::clone_disk(&a, &dir.join("b")).ok()?;
        Some(mode)
    })();
    let _ = std::fs::remove_dir_all(&dir);
    match reflink {
        Some(pocket_image::disk::CloneMode::Reflink) => v.push(check(
            "reflink",
            true,
            format!(
                "{} supports reflinks (instant pocket disks)",
                d.paths.data.display()
            ),
            None,
        )),
        Some(_) => v.push(warn(
            "reflink",
            format!(
                "{} has no reflink support; pocket disks are sparse copies",
                d.paths.data.display()
            ),
            "optional: put XDG_DATA_HOME on btrfs, xfs or bcachefs for instant disk clones",
        )),
        None => v.push(check(
            "reflink",
            false,
            format!("cannot write to {}", d.paths.data.display()),
            Some("check permissions of the pocket data directory"),
        )),
    }

    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    let path = std::ffi::CString::new(d.paths.data.as_os_str().as_encoded_bytes()).unwrap();
    let free = if unsafe { libc::statvfs(path.as_ptr(), &mut st) } == 0 {
        st.f_bavail as u64 * st.f_frsize as u64
    } else {
        0
    };
    let gib = free as f64 / (1u64 << 30) as f64;
    if gib < 2.0 {
        v.push(check(
            "disk space",
            false,
            format!("{gib:.1} GiB free in {}", d.paths.data.display()),
            Some("free up disk space or run `pocket gc`; presets need ~3 GiB"),
        ));
    } else if gib < 10.0 {
        v.push(warn(
            "disk space",
            format!("{gib:.1} GiB free"),
            "presets and pockets may need 10 GiB or more",
        ));
    } else {
        v.push(check(
            "disk space",
            true,
            format!("{gib:.0} GiB free in {}", d.paths.data.display()),
            None,
        ));
    }

    let assets_fix = "install the pocket assets (from a source checkout: `cargo xtask assets`, then set POCKET_ASSETS_DIR=target/pocket)";
    let missing: Vec<String> = [d.paths.kernel(), d.paths.system_image(), d.paths.vmm()]
        .iter()
        .filter(|p| !p.exists())
        .map(|p| p.display().to_string())
        .collect();
    v.push(check(
        "assets",
        missing.is_empty(),
        if missing.is_empty() {
            format!(
                "kernel, system image and VMM in {}",
                d.paths.assets.display()
            )
        } else {
            format!("missing: {}", missing.join(", "))
        },
        Some(assets_fix),
    ));
    v.push(check(
        "versions",
        true,
        format!(
            "pocketd {}, guest protocol v{}, {} {}",
            env!("CARGO_PKG_VERSION"),
            pocket_proto::guest::PROTO_VERSION,
            d.backend.name(),
            d.backend.version()
        ),
        None,
    ));
    for (tool, arg, fix) in [
        ("mkfs.ext4", "-V", "install e2fsprogs"),
        ("mkfs.erofs", "-V", "install erofs-utils (≥ 1.8)"),
        ("git", "--version", "install git"),
    ] {
        let path = d.paths.tool(tool);
        let ver = tool_version(&path.to_string_lossy(), arg);
        v.push(check(
            tool,
            ver.is_some(),
            ver.unwrap_or_else(|| format!("{tool} not found")),
            Some(fix),
        ));
    }
    for name in presets::names() {
        match presets::resolve(d, name) {
            Ok(img) => v.push(check(
                &format!("preset {name}"),
                true,
                format!("built: {}", img.path.display()),
                None,
            )),
            Err(_) => v.push(warn(
                &format!("preset {name}"),
                "not built yet",
                &format!("`pocket pull {name}` (or `pocket new` builds it on first use)"),
            )),
        }
    }
    if let Ok(list) = crate::images::list(d) {
        let unused: Vec<_> = list
            .iter()
            .filter(|i| !i.current && i.used_by.is_empty())
            .collect();
        if !unused.is_empty() {
            let bytes: u64 = unused.iter().map(|i| i.size_bytes).sum();
            v.push(warn(
                "old images",
                format!(
                    "{} unused image version(s), {:.1} GiB ({})",
                    unused.len(),
                    bytes as f64 / (1u64 << 30) as f64,
                    if unused.iter().all(|i| i.shared) {
                        "in POCKET_PRESET_CACHE, which pocket never cleans on its own"
                    } else {
                        "left from before automatic cleanup"
                    }
                ),
                "`pocket images` lists them; `pocket gc` removes them",
            ));
        }
    }
    v
}
