use std::time::{Duration, Instant};

use pocket_proto::guest::{ExitStatus, HostReq, Reply};
use pocket_tests::guest::{Control, exec};
use pocket_tests::{BOOT_ARGS, kvm_or_skip, scratch_dir};
use pocket_vmm::cloud_hypervisor::CloudHypervisor;
use pocket_vmm::{
    CgroupSpec, DiskRole, DiskSpec, DiskTransport, StopMode, VmSpec, VmmBackend, cgroup,
    guest_devices, process,
};

const T: Duration = Duration::from_secs(10);

#[tokio::test(flavor = "multi_thread")]
async fn create_pause_resume_stop_in_a_cgroup_scope() {
    let Some(a) = kvm_or_skip() else { return };
    let ch = CloudHypervisor::new(a.vmm.clone()).unwrap();
    let caps = ch.capabilities();
    eprintln!("backend {} {} caps {caps:?}", ch.name(), ch.version());
    assert!(caps.pmem_dax && caps.free_page_reporting && caps.lazy_restore);

    let dir = scratch_dir("backend");
    let disks = vec![
        DiskSpec {
            role: DiskRole::System,
            path: a.system.clone(),
            read_only: true,
            transport: DiskTransport::Blk,
        },
        DiskSpec {
            role: DiskRole::Base,
            path: a.base.clone(),
            read_only: true,
            transport: DiskTransport::Pmem { dax: true },
        },
    ];
    let devs = guest_devices(&disks);
    let unit = format!("pocket-test-{}", std::process::id());
    let spec = VmSpec {
        id: "backend".into(),
        vcpus: 2,
        memory_mib: 256,
        kernel: a.kernel.clone(),
        cmdline: format!("{BOOT_ARGS} pocket.base={}", devs[1]),
        disks,
        vsock_cid: 3,
        cgroup: Some(CgroupSpec {
            unit: unit.clone(),
            slice: "pocket-test.slice".into(),
            cpu_quota_pct: 150,
            memory_max_bytes: 768 << 20,
            tasks_max: 333,
        }),
        runtime_dir: dir.clone(),
        log_path: dir.join("vmm.log"),
        serial_log: None,
        shared_fs: vec![],
    };
    let t0 = Instant::now();
    let vm = ch.create(&spec).await.unwrap();
    let uds = ch.vsock_uds(&vm);
    let uds2 = uds.clone();
    let mut ctl = tokio::task::spawn_blocking(move || Control::connect(&uds2, T))
        .await
        .unwrap();
    eprintln!("create → Ready: {:?}", t0.elapsed());

    if cgroup::systemd_scopes_available() {
        let cg = cgroup::cgroup_dir(vm.pid).unwrap();
        let read = |f: &str| {
            std::fs::read_to_string(cg.join(f))
                .unwrap()
                .trim()
                .to_string()
        };
        eprintln!(
            "{}: memory.max={} cpu.max={} pids.max={}",
            cg.display(),
            read("memory.max"),
            read("cpu.max"),
            read("pids.max")
        );
        assert!(
            cg.ends_with(format!("pocket-test.slice/{unit}.scope")),
            "{cg:?}"
        );
        assert_eq!(read("memory.max"), (768u64 << 20).to_string());
        assert_eq!(read("cpu.max"), "150000 100000");
        assert_eq!(read("pids.max"), "333");
    } else {
        assert_ne!(
            std::env::var("POCKET_KVM_TESTS").as_deref(),
            Ok("require"),
            "systemd user scopes unavailable"
        );
    }

    ch.pause(&vm).await.unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let uds2 = uds.clone();
    let worker = std::thread::spawn(move || {
        let r = exec(&mut ctl, &uds2, &["/bin/echo", "after-resume"]);
        tx.send(Instant::now()).unwrap();
        (r, ctl)
    });
    assert!(
        rx.recv_timeout(Duration::from_millis(500)).is_err(),
        "a paused guest answered"
    );
    let resumed = Instant::now();
    ch.resume(&vm).await.unwrap();
    let answered = rx.recv_timeout(T).unwrap();
    assert!(answered >= resumed);
    let (r, mut ctl) = worker.join().unwrap();
    assert_eq!(
        (r.status, r.out().trim()),
        (ExitStatus::Code(0), "after-resume")
    );

    ch.adopt(&vm).await.unwrap();
    let id = ctl.send_req(HostReq::Shutdown { timeout_ms: 2000 });
    assert_eq!(ctl.wait_reply(id), Ok(Reply::Done));
    ch.stop(&vm, StopMode::Graceful { timeout_ms: 5000 })
        .await
        .unwrap();
    assert!(!process::alive(vm.pid, vm.start_time));
    assert!(ch.adopt(&vm).await.is_err());

    // Kill path on a second VM.
    let spec2 = VmSpec {
        id: "backend2".into(),
        cgroup: None,
        ..spec
    };
    let vm2 = ch.create(&spec2).await.unwrap();
    ch.stop(&vm2, StopMode::Kill).await.unwrap();
    assert!(!process::alive(vm2.pid, vm2.start_time));
    let _ = std::fs::remove_dir_all(dir);
}
