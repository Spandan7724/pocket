use std::process::Command;
use std::time::Duration;

use pocket_proto::guest::{HostReq, Reply};
use pocket_tests::guest::{Control, sh};
use pocket_tests::{TestVm, VmOpts, kvm_or_skip, make_ext4, scratch_dir};

const T: Duration = Duration::from_secs(10);

#[test]
fn orphans_are_reparented_to_init_and_reaped() {
    let Some(a) = kvm_or_skip() else { return };
    let vm = TestVm::boot(&a, "reap", VmOpts::default());
    let u = &vm.vsock_uds;
    let mut ctl = Control::connect(u, T);

    // Each subshell starts a sleeper and exits at once, orphaning it. The sleepers must not
    // hold the exec's stdout open, or the exec would only finish when they do.
    let out = sh(
        &mut ctl,
        u,
        "for i in $(seq 20); do (sleep 1 </dev/null >/dev/null 2>&1 & echo $!); done",
    );
    let pids: Vec<&str> = out.split_whitespace().collect();
    assert_eq!(pids.len(), 20);
    let ppids = sh(
        &mut ctl,
        u,
        &format!(
            "for p in {}; do awk '/^PPid/ {{print $2}}' /proc/$p/status; done",
            pids.join(" ")
        ),
    );
    let ppids: Vec<&str> = ppids.split_whitespace().collect();
    assert_eq!(
        ppids,
        vec!["1"; 20],
        "orphans were not re-parented to pocket-init"
    );

    std::thread::sleep(Duration::from_millis(2000));
    let zombies = sh(
        &mut ctl,
        u,
        "grep -l '^State:.Z' /proc/[0-9]*/status 2>/dev/null | wc -l",
    );
    assert_eq!(zombies.trim(), "0", "zombies left behind");
    let alive = sh(
        &mut ctl,
        u,
        &format!(
            "n=0; for p in {}; do [ -e /proc/$p ] && n=$((n+1)); done; echo $n",
            pids.join(" ")
        ),
    );
    assert_eq!(alive.trim(), "0");
    eprintln!("20 orphans re-parented to PID 1 and reaped; 0 zombies");
}

fn fsck(disk: &std::path::Path) -> (i32, String) {
    let o = Command::new("e2fsck")
        .arg("-fn")
        .arg(disk)
        .output()
        .expect("e2fsck (e2fsprogs) required");
    let text =
        String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr);
    (o.status.code().unwrap_or(-1), text)
}

/// The ext4 `needs_recovery` feature is set while mounted and cleared by a clean unmount
/// or read-only remount; `e2fsck -n` alone skips journal recovery and does not flag it.
fn needs_recovery(disk: &std::path::Path) -> bool {
    let o = Command::new("dumpe2fs")
        .arg("-h")
        .arg(disk)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&o.stdout);
    let features = text
        .lines()
        .find(|l| l.starts_with("Filesystem features:"))
        .unwrap_or_default();
    features.split_whitespace().any(|f| f == "needs_recovery")
}

fn debugfs_cat(disk: &std::path::Path, path: &str) -> String {
    let o = Command::new("debugfs")
        .args(["-R", &format!("cat {path}")])
        .arg(disk)
        .output()
        .unwrap();
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn shutdown_unmounts_cleanly_and_disk_passes_fsck() {
    let Some(a) = kvm_or_skip() else { return };
    let dir = scratch_dir("shutdown-disks");
    let (clean, dirty) = (dir.join("clean.raw"), dir.join("dirty.raw"));
    make_ext4(&clean, 128);
    make_ext4(&dirty, 128);

    let write = "echo persisted > /work/result && mkdir -p /home/dev && echo hi > /home/dev/x && \
                 echo upper > /etc/pocket-upper && (sleep 300 </dev/null >/dev/null 2>&1 &) && echo started";

    // Negative control: kill the VM without Shutdown → the journal still needs recovery.
    let mut vm = TestVm::boot(
        &a,
        "dirty",
        VmOpts {
            pocket_disk: Some(dirty.clone()),
            ..Default::default()
        },
    );
    let mut ctl = Control::connect(&vm.vsock_uds, T);
    sh(&mut ctl, &vm.vsock_uds, write);
    std::thread::sleep(Duration::from_millis(300));
    drop(ctl);
    drop(vm);
    eprintln!("killed VM: needs_recovery={}", needs_recovery(&dirty));
    assert!(
        needs_recovery(&dirty),
        "a killed VM should leave the journal unrecovered"
    );

    vm = TestVm::boot(
        &a,
        "clean",
        VmOpts {
            pocket_disk: Some(clean.clone()),
            ..Default::default()
        },
    );
    let mut ctl = Control::connect(&vm.vsock_uds, T);
    sh(&mut ctl, &vm.vsock_uds, write);
    // The background `sleep 300` must be terminated by Shutdown, not block it.
    let id = ctl.send_req(HostReq::Shutdown { timeout_ms: 2000 });
    assert_eq!(ctl.wait_reply(id), Ok(Reply::Done));
    let st = vm.wait_exit(T);
    assert!(
        st.is_some_and(|s| s.success()),
        "VM did not power off: {st:?}\n{}",
        vm.logs()
    );
    let serial = std::fs::read_to_string(&vm.serial_log).unwrap();
    assert!(serial.contains("pocket-init: shutdown: clean"), "{serial}");

    let (rc, text) = fsck(&clean);
    eprintln!(
        "after Shutdown: needs_recovery={}, e2fsck -fn rc={rc}\n{text}",
        needs_recovery(&clean)
    );
    assert_eq!(rc, 0, "{text}");
    assert!(!needs_recovery(&clean), "journal not committed by Shutdown");
    assert!(!text.contains("skipping journal recovery"), "{text}");
    assert_eq!(debugfs_cat(&clean, "/work/result"), "persisted\n");
    assert_eq!(debugfs_cat(&clean, "/home/dev/x"), "hi\n");
    assert_eq!(
        debugfs_cat(&clean, "/root/upper/etc/pocket-upper"),
        "upper\n"
    );
    std::fs::remove_dir_all(dir).unwrap();
}
