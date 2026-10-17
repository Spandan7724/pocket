//! Warm pool (PERFORMANCE.md §Tier 3): VMs restored from the hot template, connected and
//! paused. Claiming one is a resume plus the restore hook. Pool VMs belong to no pocket and
//! die with the daemon; the next daemon kills any it finds recorded on disk.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pocket_proto::rpc::{ErrorCode, PoolInfo};
use pocket_vmm::{CgroupSpec, StopMode, VmHandle, VmSpec};

use crate::daemon::{Daemon, EventRx, R, err, hex, random_bytes};
use crate::guest::GuestConn;
use crate::templates::{self, Template};

pub struct PoolVm {
    pub id: String,
    pub key: String,
    pub memory_mib: u32,
    vm: VmHandle,
    guest: Arc<GuestConn>,
    rx: EventRx,
}

impl PoolVm {
    pub fn into_parts(self) -> (VmHandle, Arc<GuestConn>, EventRx) {
        (self.vm, self.guest, self.rx)
    }
}

#[derive(Default)]
pub struct Pool {
    vms: Mutex<Vec<PoolVm>>,
    claimed: std::sync::atomic::AtomicU64,
    filling: AtomicBool,
    wake: Arc<tokio::sync::Notify>,
}

fn records_dir(d: &Daemon) -> PathBuf {
    d.paths.data.join("pool")
}

/// Most recently used base template whose image is still current.
fn hot(d: &Daemon) -> Option<(Template, crate::presets::Image)> {
    let mut all = d.db(|s| s.templates()).ok()?;
    all.retain(|t| t.kind == "base");
    all.sort_by_key(|t| std::cmp::Reverse(t.last_used_at));
    all.into_iter().find_map(|r| {
        let t = templates::find(d, &r.key)?;
        let img = crate::presets::resolve(d, &t.meta.preset).ok()?;
        (img.digest == t.meta.image_digest).then_some((t, img))
    })
}

impl Pool {
    /// A pooled VM restored from template `key`, if one is ready.
    pub fn take(&self, key: &str) -> Option<PoolVm> {
        let mut v = self.vms.lock().unwrap();
        let i = v.iter().position(|p| p.key == key)?;
        self.claimed.fetch_add(1, Ordering::Relaxed);
        self.wake.notify_one();
        Some(v.remove(i))
    }

    pub fn kick(&self) {
        self.wake.notify_one();
    }

    pub fn info(&self, d: &Daemon) -> PoolInfo {
        let v = self.vms.lock().unwrap();
        PoolInfo {
            enabled: enabled(d),
            size: d.config.pool_size,
            max_total_memory_mib: d.config.pool_max_memory_mib,
            template: hot(d).map(|(t, _)| t.meta.key),
            ready: v.len() as u32,
            memory_mib: v.iter().map(|p| p.memory_mib as u64).sum(),
            claimed: self.claimed.load(Ordering::Relaxed),
        }
    }
}

fn enabled(d: &Daemon) -> bool {
    d.config.pool_enabled && d.config.pool_size > 0 && templates::templates_enabled()
}

/// Background refill: after claims, new templates, and every few seconds.
pub fn spawn(d: &Arc<Daemon>) {
    cleanup_orphans(d);
    let weak = Arc::downgrade(d);
    tokio::spawn(async move {
        loop {
            let Some(d) = weak.upgrade() else { return };
            refill(&d).await;
            let wake = d.pool.wake.clone();
            drop(d);
            let _ = tokio::time::timeout(Duration::from_secs(5), wake.notified()).await;
        }
    });
}

async fn refill(d: &Arc<Daemon>) {
    if d.pool.filling.swap(true, Ordering::SeqCst) {
        return;
    }
    let hot = if enabled(d) { hot(d) } else { None };
    // VMs of other (stale or colder) templates go first.
    let stale: Vec<PoolVm> = {
        let mut v = d.pool.vms.lock().unwrap();
        let keep = hot.as_ref().map(|(t, _)| t.meta.key.clone());
        let (stay, go): (Vec<_>, Vec<_>) = std::mem::take(&mut *v)
            .into_iter()
            .partition(|p| Some(&p.key) == keep.as_ref());
        *v = stay;
        go
    };
    for p in stale {
        discard(d, p).await;
    }
    if let Some((t, img)) = hot {
        loop {
            let (n, mem) = {
                let v = d.pool.vms.lock().unwrap();
                (
                    v.len() as u32,
                    v.iter().map(|p| p.memory_mib as u64).sum::<u64>(),
                )
            };
            if n >= d.config.pool_size
                || mem + t.meta.shape.memory_mib as u64 > d.config.pool_max_memory_mib
            {
                break;
            }
            match spawn_one(d, &t, &img).await {
                Ok(p) => {
                    tracing::info!("pool: {} ready (template {})", p.id, p.key);
                    d.pool.vms.lock().unwrap().push(p);
                }
                Err(e) => {
                    tracing::warn!("pool: restore from {} failed: {}", t.meta.key, e.message);
                    break;
                }
            }
        }
    }
    d.pool.filling.store(false, Ordering::SeqCst);
}

async fn spawn_one(d: &Arc<Daemon>, t: &Template, img: &crate::presets::Image) -> R<PoolVm> {
    let id = hex(&random_bytes(8));
    let dir = d.paths.pocket_dir(&id);
    let rt = d.paths.pocket_runtime(&id);
    let io = |what: &str, e: std::io::Error| err(ErrorCode::HostSetup, format!("{what}: {e}"));
    std::fs::create_dir_all(&dir).map_err(|e| io("create pool dir", e))?;
    std::fs::create_dir_all(&rt).map_err(|e| io("create pool runtime dir", e))?;
    pocket_image::disk::clone_disk(&t.disk(), &dir.join("disk.raw"))
        .map_err(|e| err(ErrorCode::HostSetup, e.to_string()))?;
    let shape = t.meta.shape;
    let spec = VmSpec {
        id: id.clone(),
        vcpus: shape.vcpus,
        memory_mib: shape.memory_mib,
        kernel: d.paths.kernel(),
        cmdline: String::new(),
        disks: templates::template_disks(d, &img.path, &dir.join("disk.raw")),
        vsock_cid: t.meta.vsock_cid,
        cgroup: Some(CgroupSpec {
            unit: format!("pocket-pool-{}", &id[..8]),
            slice: "pocket.slice".into(),
            cpu_quota_pct: shape.vcpus as u32 * 100,
            memory_max_bytes: ((shape.memory_mib as u64) << 20) + (1 << 30),
            tasks_max: 4096,
        }),
        runtime_dir: rt.clone(),
        log_path: dir.join("vmm.log"),
        serial_log: None,
        shared_fs: vec![],
    };
    let result = async {
        let vm = d
            .backend
            .restore(&t.snapshot(), &spec)
            .await
            .map_err(|e| err(ErrorCode::Vmm, e.to_string()))?;
        let rec = records_dir(d);
        let _ = std::fs::create_dir_all(&rec);
        let _ = std::fs::write(
            rec.join(format!("{id}.json")),
            serde_json::to_vec(&vm).unwrap(),
        );
        let ready = async {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            let guest = GuestConn::connect(&vm.vsock_uds, Duration::from_secs(10), tx)
                .await
                .map_err(|e| err(ErrorCode::Guest, format!("pool guest: {e}")))?;
            // Fault the restore hook's guest pages in now (copy-on-write memory makes the
            // first touch slow), then seal again: the claim runs the real hook.
            crate::daemon::restore_hook(
                &guest,
                "pocket-pool",
                &hex(&random_bytes(16)),
                0,
                crate::daemon::Restore::Clone,
            )
            .await?;
            guest
                .request(pocket_proto::guest::HostReq::Seal)
                .await
                .map_err(|e| err(ErrorCode::Guest, format!("seal pool VM: {e}")))?;
            d.backend
                .pause(&vm)
                .await
                .map_err(|e| err(ErrorCode::Vmm, e.to_string()))?;
            Ok::<_, pocket_proto::rpc::RpcError>((guest, rx))
        }
        .await;
        match ready {
            Ok((guest, rx)) => Ok(PoolVm {
                id: id.clone(),
                key: t.meta.key.clone(),
                memory_mib: shape.memory_mib,
                vm,
                guest,
                rx,
            }),
            Err(e) => {
                let _ = d.backend.stop(&vm, StopMode::Kill).await;
                Err(e)
            }
        }
    }
    .await;
    if result.is_err() {
        forget(d, &id);
    }
    result
}

/// A claimed VM became a pocket: it is no longer the pool's to clean up.
pub fn claimed(d: &Daemon, id: &str) {
    let _ = std::fs::remove_file(records_dir(d).join(format!("{id}.json")));
}

fn forget(d: &Daemon, id: &str) {
    claimed(d, id);
    let _ = std::fs::remove_dir_all(d.paths.pocket_dir(id));
    let _ = std::fs::remove_dir_all(d.paths.pocket_runtime(id));
}

async fn discard(d: &Daemon, p: PoolVm) {
    let _ = d.backend.stop(&p.vm, StopMode::Kill).await;
    forget(d, &p.id);
}

/// Daemon shutdown: pooled VMs are disposable.
pub async fn drain(d: &Daemon) {
    let all: Vec<PoolVm> = std::mem::take(&mut *d.pool.vms.lock().unwrap());
    for p in all {
        discard(d, p).await;
    }
}

/// Pool VMs recorded by a daemon that died without draining.
fn cleanup_orphans(d: &Arc<Daemon>) {
    let dir = records_dir(d);
    for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
        let path = e.path();
        let Some(id) = path.file_stem().map(|s| s.to_string_lossy().into_owned()) else {
            continue;
        };
        if let Ok(vm) =
            serde_json::from_slice::<VmHandle>(&std::fs::read(&path).unwrap_or_default())
        {
            let d = d.clone();
            tokio::spawn(async move {
                // stop() checks pid and start time, so a reused pid is left alone.
                let _ = d.backend.stop(&vm, StopMode::Kill).await;
                forget(&d, &id);
            });
        } else {
            forget(d, &id);
        }
    }
}
