//! Pause / hibernate / resume and the idle manager (PERFORMANCE.md §Idle management).
//! Pause freezes the vCPUs; hibernate snapshots the sealed guest to the pocket dir and stops
//! the VMM; resume from either runs the restore hook (clock, RNG) before anything else.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use pocket_proto::guest::HostReq;
use pocket_proto::rpc::{ErrorCode, PocketInfo, PocketState};
use pocket_store::PocketRecord;
use pocket_vmm::{SnapshotRef, StopMode};

use crate::daemon::{Daemon, Launch, Live, R, Restore, err, now_ms, restore_hook};

/// CPU use of an idle guest's VMM stays far below this share of one CPU.
const BUSY_CPU_PCT: f64 = 5.0;

fn vmm_err(e: pocket_vmm::VmmError) -> pocket_proto::rpc::RpcError {
    err(ErrorCode::Vmm, e.to_string())
}

impl Daemon {
    pub async fn pause(self: &Arc<Self>, name: &str) -> R<PocketInfo> {
        let rec = self.find(name)?;
        let lock = self.op_lock(&rec.info.id);
        let _g = lock.lock().await;
        let live = self.running(&rec)?;
        if !live.paused.load(Ordering::SeqCst) {
            self.backend.pause(&live.vm).await.map_err(vmm_err)?;
            live.paused.store(true, Ordering::SeqCst);
            self.set_state(&rec, PocketState::Paused)?;
        }
        Ok(self.info(self.find(&rec.info.name)?))
    }

    /// Resumes a paused or hibernated pocket (no-op when running).
    pub async fn resume(self: &Arc<Self>, name: &str) -> R<PocketInfo> {
        let rec = self.find(name)?;
        let lock = self.op_lock(&rec.info.id);
        let _g = lock.lock().await;
        self.resume_locked(&self.find(&rec.info.name)?).await?;
        Ok(self.info(self.find(&rec.info.name)?))
    }

    /// Makes a pocket runnable for a request that needs its guest (attach, exec, diff…).
    /// Boxed: resuming boots, and booting sets up port forwards that call this.
    pub fn wake<'a>(
        self: &'a Arc<Self>,
        name: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = R<()>> + Send + 'a>> {
        Box::pin(async move {
            let rec = self.find(name)?;
            if !matches!(
                rec.info.state,
                PocketState::Paused | PocketState::Hibernated
            ) {
                return Ok(());
            }
            let lock = self.op_lock(&rec.info.id);
            let _g = lock.lock().await;
            self.resume_locked(&self.find(&rec.info.name)?).await
        })
    }

    async fn resume_locked(self: &Arc<Self>, rec: &PocketRecord) -> R<()> {
        match rec.info.state {
            PocketState::Paused => {
                let live = self.running(rec)?;
                self.resume_live(rec, &live).await
            }
            PocketState::Hibernated => self.resume_hibernated(rec).await.map(|_| ()),
            _ => Ok(()),
        }
    }

    async fn resume_live(&self, rec: &PocketRecord, live: &Live) -> R<()> {
        let started = Instant::now();
        self.backend.resume(&live.vm).await.map_err(vmm_err)?;
        live.paused.store(false, Ordering::SeqCst);
        // The guest clock stood still while paused; reseed too, it costs nothing.
        let mut meta = Self::meta(rec);
        meta.restore_generation += 1;
        let mid = meta.machine_id.clone().unwrap_or_default();
        if !mid.is_empty() {
            restore_hook(
                &live.guest,
                &rec.info.name,
                &mid,
                meta.restore_generation,
                Restore::Own,
            )
            .await?;
            self.save_meta(&rec.info.id, &meta)?;
        }
        let _ = self.db(|s| s.touch(&rec.info.id, now_ms()));
        self.set_state(rec, PocketState::Running)?;
        tracing::info!(
            "{}: resumed in {:.1} ms",
            rec.info.name,
            started.elapsed().as_secs_f64() * 1e3
        );
        Ok(())
    }

    async fn resume_hibernated(self: &Arc<Self>, rec: &PocketRecord) -> R<Arc<Live>> {
        let started = Instant::now();
        let meta = Self::meta(rec);
        let (dir, fp) = meta.hibernation.clone().ok_or_else(|| {
            err(
                ErrorCode::InvalidState,
                format!("pocket {} has no hibernation image", rec.info.name),
            )
            .hint(format!("start it with `pocket start {}`", rec.info.name))
        })?;
        let snap = SnapshotRef {
            dir: self.paths.pocket_dir(&rec.info.id).join(&dir),
            backend: self.backend.name().into(),
            host_fingerprint: fp,
            disks: vec![],
        };
        // The saved memory refers to the exact image it ran on, never a newer build.
        let resumed =
            match crate::presets::resolve_version(self, &rec.info.preset, &rec.info.image_digest) {
                Ok(image) => self
                    .boot(rec, &image.path, Launch::Hibernation(snap))
                    .await
                    .map_err(|e| e.message),
                Err(e) => Err(e.message),
            };
        let live = match resumed {
            Ok(l) => l,
            Err(why) => {
                // Unusable (image gone, host kernel / VMM changed, file damaged): boot the
                // disk on the current image instead; running processes are lost, files not.
                tracing::warn!(
                    "{}: resume from hibernation failed ({why}); booting the disk",
                    rec.info.name
                );
                let image = crate::presets::resolve(self, &rec.info.preset)?;
                let live = self.boot(rec, &image.path, Launch::Cold).await?;
                self.db(|s| s.set_image_digest(&rec.info.id, &image.digest))?;
                self.create_session(&live, Some("shell"), None, 24, 80, None)
                    .await?;
                live
            }
        };
        let _ = self.db(|s| s.touch(&rec.info.id, now_ms()));
        self.set_state(rec, PocketState::Running)?;
        tracing::info!(
            "{}: resumed from hibernation in {:.1} ms",
            rec.info.name,
            started.elapsed().as_secs_f64() * 1e3
        );
        Ok(live)
    }

    pub async fn hibernate(self: &Arc<Self>, name: &str) -> R<PocketInfo> {
        let rec = self.find(name)?;
        let lock = self.op_lock(&rec.info.id);
        let _g = lock.lock().await;
        let rec = self.find(&rec.info.name)?;
        if rec.info.state == PocketState::Hibernated {
            return Ok(self.info(rec));
        }
        let live = self.running(&rec)?;
        let m = Self::meta(&rec);
        if !m.shares.is_empty() || m.net_mode.as_deref() == Some("full") {
            return Err(err(
                ErrorCode::InvalidState,
                format!(
                    "pocket {} has shared folders or a network card",
                    rec.info.name
                ),
            )
            .hint(
                "pockets with --share-dir or --net full can be paused or stopped, not hibernated",
            ));
        }
        let started = Instant::now();
        if live.paused.load(Ordering::SeqCst) {
            self.backend.resume(&live.vm).await.map_err(vmm_err)?;
            live.paused.store(false, Ordering::SeqCst);
        }
        live.guest
            .request(HostReq::Seal)
            .await
            .map_err(|e| err(ErrorCode::Guest, format!("seal for hibernation: {e}")))?;
        let dir_name = format!("hibernate-{}", now_ms());
        let dir = self.paths.pocket_dir(&rec.info.id).join(&dir_name);
        let snap = async {
            self.backend.pause(&live.vm).await.map_err(vmm_err)?;
            self.backend.snapshot(&live.vm, &dir).await.map_err(vmm_err)
        }
        .await;
        let snap = match snap {
            Ok(s) => s,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                let _ = self.backend.resume(&live.vm).await;
                let meta = Self::meta(&rec);
                if let Some(mid) = &meta.machine_id {
                    let _ = restore_hook(
                        &live.guest,
                        &rec.info.name,
                        mid,
                        meta.restore_generation + 1,
                        Restore::Own,
                    )
                    .await;
                }
                return Err(e);
            }
        };
        crate::templates::set_private(&dir);
        live.stopping.store(true, Ordering::SeqCst);
        let _ = self.backend.stop(&live.vm, StopMode::Kill).await;
        self.live.lock().unwrap().remove(&rec.info.id);
        self.db(|s| s.set_vm(&rec.info.id, None))?;
        let mut meta = Self::meta(&rec);
        meta.hibernation = Some((dir_name.clone(), snap.host_fingerprint));
        self.save_meta(&rec.info.id, &meta)?;
        remove_hibernations(self, &rec.info.id, Some(&dir_name));
        self.set_state(&rec, PocketState::Hibernated)?;
        tracing::info!(
            "{}: hibernated in {:.1?} ({} MiB on disk)",
            rec.info.name,
            started.elapsed(),
            crate::templates::du(&dir) >> 20
        );
        Ok(self.info(self.find(&rec.info.name)?))
    }
}

/// Removes hibernation images of a pocket except `keep`. Only called when no VM maps them.
pub fn remove_hibernations(d: &Daemon, id: &str, keep: Option<&str>) {
    let dir = d.paths.pocket_dir(id);
    for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if n.starts_with("hibernate-") && Some(n.as_str()) != keep {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

struct Track {
    sessions: HashMap<String, pocket_proto::rpc::SessionState>,
    cpu_ticks: Option<u64>,
    output_ms: u64,
    touched: u64,
    net_ms: u64,
    last_active: Instant,
    checked: Instant,
}

/// What the idle manager saw for a pocket in one tick.
#[derive(Debug, Default, Clone, Copy)]
pub struct Signals {
    pub attached: bool,
    pub output: bool,
    pub cpu_busy: bool,
    pub net: bool,
    pub rpc: bool,
}

impl Signals {
    pub fn active(&self) -> bool {
        self.attached || self.output || self.cpu_busy || self.net || self.rpc
    }
}

fn thresholds(d: &Daemon, rec: &PocketRecord) -> (u64, u64) {
    let m = Daemon::meta(rec);
    (
        m.idle_pause_ms.unwrap_or(d.config.idle_pause_ms),
        m.idle_hibernate_ms.unwrap_or(d.config.idle_hibernate_ms),
    )
}

/// Pauses pockets idle for `pause_after`, hibernates them after `hibernate_after`. A pocket
/// with an attached client, PTY output, CPU use or open network streams is active.
pub fn spawn_idle_manager(d: &Arc<Daemon>) {
    let weak = Arc::downgrade(d);
    let tick = Duration::from_millis(d.config.idle_tick_ms);
    tokio::spawn(async move {
        let mut tracks: HashMap<String, Track> = HashMap::new();
        loop {
            tokio::time::sleep(tick).await;
            let Some(d) = weak.upgrade() else { return };
            let Ok(recs) = d.db(|s| s.pockets()) else {
                continue;
            };
            tracks.retain(|id, _| recs.iter().any(|r| &r.info.id == id));
            for rec in recs {
                let (pause_ms, hib_ms) = thresholds(&d, &rec);
                match rec.info.state {
                    PocketState::Running => {
                        let Some(live) = d.live(&rec.info.id) else {
                            continue;
                        };
                        let s = signals(&d, &rec, &live, &mut tracks).await;
                        let t = &tracks[&rec.info.id];
                        let idle = t.last_active.elapsed();
                        if !s.active() && pause_ms > 0 && idle >= Duration::from_millis(pause_ms) {
                            tracing::info!("{}: idle for {:.0?}; pausing", rec.info.name, idle);
                            if let Err(e) = d.pause(&rec.info.name).await {
                                tracing::warn!("{}: idle pause: {}", rec.info.name, e.message);
                            }
                        }
                    }
                    PocketState::Paused => {
                        let Some(t) = tracks.get(&rec.info.id) else {
                            // Paused by hand before we saw it: count from now.
                            tracks.insert(rec.info.id.clone(), fresh(None));
                            continue;
                        };
                        let net = d.activity(&rec.info.id).open.load(Ordering::SeqCst) > 0;
                        let m = Daemon::meta(&rec);
                        let hibernatable =
                            m.shares.is_empty() && m.net_mode.as_deref() != Some("full");
                        if !net
                            && hibernatable
                            && hib_ms > 0
                            && t.last_active.elapsed() >= Duration::from_millis(hib_ms)
                        {
                            tracing::info!(
                                "{}: idle for {:.0?}; hibernating",
                                rec.info.name,
                                t.last_active.elapsed()
                            );
                            if let Err(e) = d.hibernate(&rec.info.name).await {
                                tracing::warn!("{}: idle hibernate: {}", rec.info.name, e.message);
                            }
                        }
                    }
                    _ => {
                        tracks.remove(&rec.info.id);
                    }
                }
            }
        }
    });
}

fn fresh(cpu: Option<u64>) -> Track {
    Track {
        sessions: HashMap::new(),
        cpu_ticks: cpu,
        output_ms: 0,
        touched: 0,
        net_ms: 0,
        last_active: Instant::now(),
        checked: Instant::now(),
    }
}

async fn signals(
    d: &Daemon,
    rec: &PocketRecord,
    live: &Live,
    tracks: &mut HashMap<String, Track>,
) -> Signals {
    let cpu = pocket_vmm::process::cpu_ticks(live.vm.pid, live.vm.start_time);
    let act = d.activity(&rec.info.id);
    let net_ms = act.last_ms.load(Ordering::SeqCst);
    let sessions = tokio::time::timeout(
        Duration::from_secs(2),
        live.guest.request(HostReq::SessionList),
    )
    .await;
    let list = match sessions {
        Ok(Ok(pocket_proto::guest::Reply::Sessions(list))) => Some(list),
        _ => None,
    };
    let (attached, output_ms) = match &list {
        Some(list) => (
            list.iter().any(|s| s.attached > 0 && s.exited.is_none()),
            list.iter()
                .map(|s| s.last_output_unix_ms)
                .max()
                .unwrap_or(0),
        ),
        // An unresponsive guest is not evidence of idleness.
        None => (true, 0),
    };
    let t = tracks
        .entry(rec.info.id.clone())
        .or_insert_with(|| fresh(cpu));
    for s in list.iter().flatten() {
        use pocket_proto::rpc::{SessionState, session_state};
        let st = session_state(s, now_ms());
        let before = t.sessions.insert(s.name.clone(), st);
        // Bells and OSC notifications were shown as they arrived; this catches agents that
        // just sit at a prompt.
        let signalled =
            s.last_bell_unix_ms > 0 && s.last_bell_unix_ms + 1500 >= s.last_output_unix_ms;
        if st == SessionState::Waiting
            && before.is_some_and(|b| b != SessionState::Waiting)
            && !signalled
        {
            d.notice(
                live,
                Some(s.name.clone()),
                "waiting",
                &format!("pocket · {}", rec.info.name),
                &format!("{} is waiting for input: {}", s.name, s.tail.trim()),
            );
        }
    }
    let dt = t.checked.elapsed().as_secs_f64().max(0.001);
    let hz = pocket_vmm::process::clock_ticks_per_sec() as f64;
    let cpu_busy = match (cpu, t.cpu_ticks) {
        (Some(now), Some(before)) => {
            (now.saturating_sub(before)) as f64 / hz / dt * 100.0 > BUSY_CPU_PCT
        }
        _ => false,
    };
    let s = Signals {
        attached,
        output: output_ms != t.output_ms,
        cpu_busy,
        net: act.open.load(Ordering::SeqCst) > 0 || net_ms != t.net_ms,
        rpc: rec.info.last_active_at != t.touched,
    };
    t.cpu_ticks = cpu;
    t.output_ms = output_ms;
    t.net_ms = net_ms;
    t.touched = rec.info.last_active_at;
    t.checked = Instant::now();
    if s.active() {
        t.last_active = Instant::now();
    }
    tracing::debug!("{}: idle signals {s:?}", rec.info.name);
    s
}
