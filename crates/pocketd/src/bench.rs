//! `pocket bench` (PERFORMANCE.md §4): start-path and density measurements on throwaway VMs
//! that are never pockets. The CLI adds the end-to-end `pocket new` and attach numbers.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pocket_proto::guest::HostReq;
use pocket_proto::rpc::ErrorCode;
use pocket_vmm::{CgroupSpec, SnapshotRef, StopMode, VmHandle, VmSpec, guest_devices};
use serde_json::{Value, json};

use crate::daemon::{BOOT_ARGS, Daemon, R, Restore, err, hex, random_bytes, restore_hook};
use crate::guest::GuestConn;
use crate::templates::{self, Shape, Template};

pub fn stats(v: &mut [f64]) -> Value {
    if v.is_empty() {
        return Value::Null;
    }
    v.sort_by(|a, b| a.total_cmp(b));
    let pct = |p: f64| {
        let k = (v.len() - 1) as f64 * p / 100.0;
        let (lo, hi) = (k.floor() as usize, (k.ceil() as usize).min(v.len() - 1));
        v[lo] + (v[hi] - v[lo]) * (k - lo as f64)
    };
    let r = |x: f64| (x * 100.0).round() / 100.0;
    json!({ "p50": r(pct(50.0)), "p95": r(pct(95.0)), "min": r(v[0]), "max": r(v[v.len() - 1]), "n": v.len() })
}

struct BenchVm {
    vm: VmHandle,
    dir: PathBuf,
    rt: PathBuf,
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn spec(d: &Daemon, image: &Path, shape: Shape, dir: &Path, rt: &Path, id: &str) -> VmSpec {
    let disks = templates::template_disks(d, image, &dir.join("disk.raw"));
    let dev = guest_devices(&disks);
    VmSpec {
        id: id.to_string(),
        vcpus: shape.vcpus,
        memory_mib: shape.memory_mib,
        kernel: d.paths.kernel(),
        cmdline: format!(
            "{BOOT_ARGS} pocket.base={} pocket.disk={} pocket.hostname=bench",
            dev[1], dev[2]
        ),
        disks,
        vsock_cid: 3,
        cgroup: Some(CgroupSpec {
            unit: format!("pocket-bench-{}", &id[..8]),
            slice: "pocket.slice".into(),
            cpu_quota_pct: shape.vcpus as u32 * 100,
            memory_max_bytes: ((shape.memory_mib as u64) << 20) + (1 << 30),
            tasks_max: 4096,
        }),
        runtime_dir: rt.to_path_buf(),
        log_path: dir.join("vmm.log"),
        serial_log: None,
        shared_fs: vec![],
    }
}

async fn connect(vm: &VmHandle) -> R<Arc<GuestConn>> {
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    GuestConn::connect(&vm.vsock_uds, Duration::from_secs(15), tx)
        .await
        .map_err(|e| err(ErrorCode::Guest, format!("bench guest: {e}")))
}

fn scratch(d: &Daemon) -> R<(String, PathBuf, PathBuf)> {
    let id = hex(&random_bytes(8));
    let dir = d.paths.data.join("bench").join(&id);
    let rt = d.paths.runtime.join("b").join(&id[..8]);
    for p in [&dir, &rt] {
        std::fs::create_dir_all(p)
            .map_err(|e| err(ErrorCode::HostSetup, format!("create {}: {e}", p.display())))?;
    }
    Ok((id, dir, rt))
}

async fn discard(d: &Daemon, b: BenchVm) {
    let _ = d.backend.stop(&b.vm, StopMode::Kill).await;
    let _ = std::fs::remove_dir_all(&b.dir);
    let _ = std::fs::remove_dir_all(&b.rt);
}

/// Cold boot of a fresh pocket disk: VMM spawn → `Ready` received.
async fn cold(d: &Arc<Daemon>, image: &Path, shape: Shape) -> R<(f64, BenchVm)> {
    let (id, dir, rt) = scratch(d)?;
    pocket_image::disk::create_pocket_disk(
        &d.paths.templates(),
        shape.disk_bytes,
        &dir.join("disk.raw"),
    )
    .map_err(|e| err(ErrorCode::HostSetup, e.to_string()))?;
    let s = spec(d, image, shape, &dir, &rt, &id);
    let t = Instant::now();
    let vm = d
        .backend
        .create(&s)
        .await
        .map_err(|e| err(ErrorCode::Vmm, e.to_string()))?;
    let b = BenchVm { vm, dir, rt };
    match connect(&b.vm).await {
        Ok(_) => Ok((ms(t.elapsed()), b)),
        Err(e) => {
            discard(d, b).await;
            Err(e)
        }
    }
}

/// Restore from a snapshot: VMM spawn → `Ready` → restore hook answered.
async fn restore(
    d: &Arc<Daemon>,
    image: &Path,
    shape: Shape,
    snap: &SnapshotRef,
    disk_from: &Path,
) -> R<(f64, BenchVm, Arc<GuestConn>)> {
    let (id, dir, rt) = scratch(d)?;
    pocket_image::disk::clone_disk(disk_from, &dir.join("disk.raw"))
        .map_err(|e| err(ErrorCode::HostSetup, e.to_string()))?;
    let s = spec(d, image, shape, &dir, &rt, &id);
    let t = Instant::now();
    let vm = d
        .backend
        .restore(snap, &s)
        .await
        .map_err(|e| err(ErrorCode::Vmm, e.to_string()))?;
    let b = BenchVm { vm, dir, rt };
    let r = async {
        let g = connect(&b.vm).await?;
        restore_hook(&g, "bench", &hex(&random_bytes(16)), 1, Restore::Clone).await?;
        Ok::<_, pocket_proto::rpc::RpcError>(g)
    }
    .await;
    match r {
        Ok(g) => Ok((ms(t.elapsed()), b, g)),
        Err(e) => {
            discard(d, b).await;
            Err(e)
        }
    }
}

fn pss_kib(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/smaps_rollup"))
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("Pss:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap_or(0)
}

pub async fn run(
    d: &Arc<Daemon>,
    runs: u32,
    preset: &str,
    density: u32,
    memory_mib: Option<u32>,
    progress: &(dyn Fn(&str) + Send + Sync),
) -> R<String> {
    let runs = runs.clamp(1, 200) as usize;
    let image = crate::presets::resolve(d, preset)?;
    let shape = Shape {
        vcpus: crate::daemon::DEFAULT_CPUS,
        memory_mib: memory_mib
            .unwrap_or(crate::daemon::DEFAULT_MEMORY_MIB)
            .clamp(256, 1 << 20),
        disk_bytes: crate::daemon::DEFAULT_DISK_MIB << 20,
    };
    progress("snapshot template");
    let info = templates::build_now(
        d,
        preset,
        Some(shape.vcpus),
        Some(shape.memory_mib),
        progress,
    )
    .await?;
    let tpl: Template =
        templates::find(d, &info.key).ok_or_else(|| err(ErrorCode::Vmm, "template vanished"))?;

    progress(&format!("cold boot ×{runs}"));
    let mut cold_ms = vec![];
    for _ in 0..runs {
        let (t, b) = cold(d, &image.path, shape).await?;
        cold_ms.push(t);
        discard(d, b).await;
    }

    progress(&format!("template restore ×{runs}"));
    let mut restore_ms = vec![];
    for _ in 0..runs {
        let (t, b, _) = restore(d, &image.path, shape, &tpl.snapshot(), &tpl.disk()).await?;
        restore_ms.push(t);
        discard(d, b).await;
    }

    progress(&format!("pool claim ×{runs}"));
    let mut claim_ms = vec![];
    let mut resume_ms = vec![];
    for _ in 0..runs {
        let (_, b, g) = restore(d, &image.path, shape, &tpl.snapshot(), &tpl.disk()).await?;
        // Same preparation as a pool VM: warm the hook, seal, pause.
        g.request(HostReq::Seal)
            .await
            .map_err(|e| err(ErrorCode::Guest, e.to_string()))?;
        d.backend
            .pause(&b.vm)
            .await
            .map_err(|e| err(ErrorCode::Vmm, e.to_string()))?;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let t = Instant::now();
        d.backend
            .resume(&b.vm)
            .await
            .map_err(|e| err(ErrorCode::Vmm, e.to_string()))?;
        resume_ms.push(ms(t.elapsed()));
        restore_hook(&g, "bench", &hex(&random_bytes(16)), 2, Restore::Clone).await?;
        claim_ms.push(ms(t.elapsed()));
        discard(d, b).await;
    }

    progress(&format!("hibernate → resume ×{runs}"));
    let mut hib_ms = vec![];
    let mut hib_write_ms = vec![];
    let mut hib_mib = vec![];
    for _ in 0..runs {
        let (_, b, g) = restore(d, &image.path, shape, &tpl.snapshot(), &tpl.disk()).await?;
        let t = Instant::now();
        g.request(HostReq::Seal)
            .await
            .map_err(|e| err(ErrorCode::Guest, e.to_string()))?;
        d.backend
            .pause(&b.vm)
            .await
            .map_err(|e| err(ErrorCode::Vmm, e.to_string()))?;
        let sdir = b.dir.join("hibernate");
        let snap = d
            .backend
            .snapshot(&b.vm, &sdir)
            .await
            .map_err(|e| err(ErrorCode::Vmm, e.to_string()))?;
        hib_write_ms.push(ms(t.elapsed()));
        hib_mib.push((templates::du(&sdir) >> 20) as f64);
        let _ = d.backend.stop(&b.vm, StopMode::Kill).await;
        let (t2, b2, _) = restore(d, &image.path, shape, &snap, &b.dir.join("disk.raw")).await?;
        hib_ms.push(t2);
        discard(d, b2).await;
        discard(d, b).await;
    }

    let mut out = json!({
        "version": 1,
        "preset": preset,
        "image": image.digest,
        "shape": { "vcpus": shape.vcpus, "memory_mib": shape.memory_mib },
        "host": templates::fingerprint(d),
        "runs": runs,
        "template": { "key": tpl.meta.key, "size_mib": templates::du(&tpl.dir) >> 20 },
        "metrics": {
            "cold_boot_ms": stats(&mut cold_ms),
            "restore_ms": stats(&mut restore_ms),
            "pool_claim_ms": stats(&mut claim_ms),
            "pool_resume_api_ms": stats(&mut resume_ms),
            "hibernate_resume_ms": stats(&mut hib_ms),
            "hibernate_write_ms": stats(&mut hib_write_ms),
            "hibernate_image_mib": stats(&mut hib_mib),
        },
    });

    if density > 0 {
        progress(&format!("density: {density} idle VMs from the template"));
        let mut vms = vec![];
        let r = async {
            for _ in 0..density {
                let (_, b, g) = restore(d, &image.path, shape, &tpl.snapshot(), &tpl.disk()).await?;
                vms.push((b, g));
            }
            // Let free page reporting and the guests settle.
            tokio::time::sleep(Duration::from_secs(5)).await;
            let pss: Vec<u64> = vms.iter().map(|(b, _)| pss_kib(b.vm.pid)).collect();
            let disk: Vec<u64> = vms
                .iter()
                .map(|(b, _)| pocket_image::disk::allocated_bytes(&b.dir.join("disk.raw")))
                .collect();
            let total: u64 = pss.iter().sum();
            Ok::<_, pocket_proto::rpc::RpcError>(json!({
                "vms": density,
                "total_pss_mib": (total as f64 / 1024.0 * 10.0).round() / 10.0,
                "per_vm_pss_mib": (total as f64 / 1024.0 / density as f64 * 10.0).round() / 10.0,
                "guest_memory_mib": shape.memory_mib,
                "disk_per_pocket_mib": (disk.iter().sum::<u64>() as f64 / density as f64 / 1048576.0 * 10.0).round() / 10.0,
            }))
        }
        .await;
        for (b, _) in vms {
            discard(d, b).await;
        }
        out["metrics"]["density"] = r?;
    }
    let _ = std::fs::remove_dir_all(d.paths.data.join("bench"));
    Ok(serde_json::to_string_pretty(&out).unwrap())
}
