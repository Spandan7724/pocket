use std::time::{Duration, Instant};

use pocket_proto::guest::{HostReq, PROTO_VERSION, Reply};
use pocket_tests::guest::{Control, exec, sh};
use pocket_tests::{TestVm, VmOpts, kvm_or_skip, make_ext4};

fn percentile(xs: &mut [f64], p: f64) -> f64 {
    xs.sort_by(|a, b| a.total_cmp(b));
    let k = (xs.len() - 1) as f64 * p / 100.0;
    let (lo, hi) = (k.floor() as usize, k.ceil() as usize);
    xs[lo] + (xs[hi] - xs[lo]) * (k - lo as f64)
}

#[test]
fn boots_as_pid1_with_overlay_root_and_reports_ready() {
    let Some(a) = kvm_or_skip() else { return };
    let dir = pocket_tests::scratch_dir("boot-disk");
    let disk = dir.join("disk.raw");
    make_ext4(&disk, 256);
    let vm = TestVm::boot(
        &a,
        "boot",
        VmOpts {
            pocket_disk: Some(disk),
            extra_cmdline: "pocket.hostname=boot-test".into(),
            ..Default::default()
        },
    );
    let mut ctl = Control::connect(&vm.vsock_uds, Duration::from_secs(10));
    assert!(!ctl.init_version.is_empty());
    assert!(ctl.init_ns > 0 && ctl.init_ns < ctl.boot_ns);
    eprintln!(
        "pocket-init {} (protocol {PROTO_VERSION}) ready {:.1} ms after kernel start, {:.2} ms in init",
        ctl.init_version,
        ctl.boot_ns as f64 / 1e6,
        ctl.init_ns as f64 / 1e6
    );
    let u = &vm.vsock_uds;

    let pid1 = sh(&mut ctl, u, "tr '\\0' ' ' < /proc/1/cmdline");
    assert_eq!(pid1.trim(), "/pocket-init");

    let mounts = sh(&mut ctl, u, "cat /proc/mounts");
    eprintln!("{mounts}");
    let line = |mp: &str| {
        mounts
            .lines()
            .find(|l| l.split(' ').nth(1) == Some(mp))
            .unwrap_or_else(|| panic!("{mp} not mounted:\n{mounts}"))
            .to_string()
    };
    assert!(line("/").starts_with("overlay / overlay "), "{}", line("/"));
    assert!(line("/").contains("lowerdir=/run/pocket/base"));
    let base = line("/run/pocket/base");
    assert!(
        base.starts_with("/dev/pmem0 /run/pocket/base erofs ro") && base.contains("dax=always"),
        "{base}"
    );
    assert!(line("/run/pocket/disk").starts_with("/dev/vdb /run/pocket/disk ext4 rw"));
    assert!(line("/work").starts_with("/dev/vdb /work ext4 rw"));
    assert!(line("/home").starts_with("/dev/vdb /home ext4 rw"));
    assert!(line("/run/pocket/system").starts_with("/dev/root /run/pocket/system erofs ro"));
    for mp in [
        "/proc",
        "/sys",
        "/dev",
        "/dev/pts",
        "/sys/fs/cgroup",
        "/tmp",
        "/run",
    ] {
        line(mp);
    }
    // The old root really moved away: the system image's init is only under /run/pocket/system.
    assert!(sh(&mut ctl, u, "ls /run/pocket/system").contains("pocket-init"));
    assert!(
        exec(&mut ctl, u, &["/bin/ls", "/pocket-init"])
            .status
            .code()
            != 0
    );
    assert_eq!(
        sh(&mut ctl, u, "cat /etc/alpine-release")
            .trim()
            .split('.')
            .count(),
        3
    );

    assert_eq!(sh(&mut ctl, u, "hostname").trim(), "boot-test");
    let serial = std::fs::read_to_string(&vm.serial_log).unwrap();
    assert!(
        serial.contains("rng seeded with 64 bytes from virtio-rng"),
        "{serial}"
    );
    if let Some(l) = serial.lines().find(|l| l.contains("pocket-init: ready:")) {
        eprintln!("{l}");
    }
    // getrandom(2) blocks until the CRNG is initialised; with the seed it returns at once.
    let t = Instant::now();
    assert_eq!(
        sh(&mut ctl, u, "head -c 32 /dev/random | wc -c").trim(),
        "32"
    );
    assert!(t.elapsed() < Duration::from_secs(2));

    let seed: Vec<u8> = (0..64).map(|i| i * 3).collect();
    let r = ctl.request(HostReq::Configure {
        hostname: "configured".into(),
        rng_seed: seed,
        time_unix_nanos: 1_900_000_000_000_000_000,
        env: vec![("POCKET_TEST".into(), "yes".into())],
        proxy_port: 3128,
        machine_id: "00112233445566778899aabbccddeeff".into(),
    });
    assert_eq!(r, Ok(Reply::Done));
    assert_eq!(sh(&mut ctl, u, "hostname").trim(), "configured");
    assert_eq!(
        sh(&mut ctl, u, "cat /etc/machine-id").trim(),
        "00112233445566778899aabbccddeeff"
    );
    assert_eq!(sh(&mut ctl, u, "echo $POCKET_TEST").trim(), "yes");
    let year: i32 = sh(&mut ctl, u, "date -u +%Y").trim().parse().unwrap();
    assert_eq!(year, 2030);
}

#[test]
fn shutdown_without_disk_powers_off() {
    let Some(a) = kvm_or_skip() else { return };
    let mut vm = TestVm::boot(&a, "noDisk", VmOpts::default());
    let mut ctl = Control::connect(&vm.vsock_uds, Duration::from_secs(10));
    let id = ctl.send_req(HostReq::Shutdown { timeout_ms: 1000 });
    let r = ctl.wait_reply(id);
    // Without a pocket disk the remount targets tmpfs, which also succeeds.
    assert_eq!(r, Ok(Reply::Done));
    let st = vm.wait_exit(Duration::from_secs(10));
    assert!(
        st.is_some_and(|s| s.success()),
        "VM did not power off: {st:?}"
    );
}

/// Kernel handoff → Ready over POCKET_BOOT_RUNS boots (default 10) per configuration,
/// without a serial console (as pocketd will boot).
#[test]
fn boot_time_to_ready() {
    let Some(a) = kvm_or_skip() else { return };
    let runs: usize = std::env::var("POCKET_BOOT_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);
    let dir = pocket_tests::scratch_dir("timing-disk");
    for with_disk in [false, true] {
        let (mut init_ms, mut kernel_ms, mut host_ms) = (vec![], vec![], vec![]);
        for i in 0..runs {
            let pocket_disk = with_disk.then(|| {
                let d = dir.join(format!("disk{i}.raw"));
                make_ext4(&d, 256);
                d
            });
            let vm = TestVm::boot(
                &a,
                "timing",
                VmOpts {
                    serial: false,
                    pocket_disk,
                    ..Default::default()
                },
            );
            let ctl = Control::connect(&vm.vsock_uds, Duration::from_secs(10));
            host_ms.push(vm.started.elapsed().as_secs_f64() * 1e3);
            init_ms.push(ctl.init_ns as f64 / 1e6);
            kernel_ms.push(ctl.boot_ns as f64 / 1e6);
        }
        let p = |xs: &mut Vec<f64>| (percentile(xs, 50.0), percentile(xs, 95.0));
        let ((i50, i95), (k50, k95), (h50, h95)) =
            (p(&mut init_ms), p(&mut kernel_ms), p(&mut host_ms));
        eprintln!(
            "boot timing, {runs} runs, {}: kernel handoff → Ready (in pocket-init) p50 {i50:.2} ms p95 {i95:.2} ms; \
             guest boottime at Ready p50 {k50:.1} ms p95 {k95:.1} ms; host spawn → Ready received p50 {h50:.1} ms p95 {h95:.1} ms",
            if with_disk {
                "ext4 pocket disk"
            } else {
                "tmpfs upper"
            }
        );
        assert!(i95 < 100.0, "pocket-init took {i95:.1} ms to Ready");
    }
    std::fs::remove_dir_all(dir).unwrap();
}
