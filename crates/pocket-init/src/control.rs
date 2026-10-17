//! Control connections (port 1024) and data streams (port 1025).

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use pocket_proto::frame::{recv, send};
use pocket_proto::guest::{
    ErrorKind, GuestError, GuestEvent, GuestMsg, HostMsg, HostReq, MAX_FILE, PROTO_VERSION, Reply,
    StreamAck, StreamOpen,
};

use crate::{exec, log, netshim, process, session, shutdown, sys};

type Conn = Arc<Mutex<File>>;

static CONNS: Mutex<Vec<(u64, Conn)>> = Mutex::new(Vec::new());
static NEXT_CONN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub struct ReadyInfo {
    pub boot_ns: u64,
    pub init_ns: u64,
}

fn write(conn: &Conn, msg: &GuestMsg) -> bool {
    let f = conn.lock().unwrap_or_else(|e| e.into_inner());
    send(&mut &*f, msg).is_ok()
}

/// Sends an event to every connected host; drops connections that fail.
pub fn broadcast(event: GuestEvent) {
    let conns: Vec<(u64, Conn)> = CONNS.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let msg = GuestMsg::Event(event);
    for (id, c) in conns {
        if !write(&c, &msg) {
            CONNS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|(i, _)| *i != id);
        }
    }
}

pub fn serve_control(conn: File, ready: &ReadyInfo) {
    let Ok(w) = conn.try_clone() else { return };
    let w: Conn = Arc::new(Mutex::new(w));
    let hello = GuestMsg::Hello {
        proto_version: PROTO_VERSION,
        init_version: env!("CARGO_PKG_VERSION").into(),
    };
    let r = GuestMsg::Ready {
        boot_ns_since_kernel_start: ready.boot_ns,
        init_ns: ready.init_ns,
    };
    if !write(&w, &hello) || !write(&w, &r) {
        return;
    }
    match recv::<_, HostMsg>(&mut &conn) {
        Ok(Some(HostMsg::Hello { proto_version })) if proto_version == PROTO_VERSION => {}
        Ok(Some(HostMsg::Hello { proto_version })) => {
            log!("host speaks protocol {proto_version}, we speak {PROTO_VERSION}; closing");
            return;
        }
        other => {
            log!("control connection did not start with Hello: {other:?}");
            return;
        }
    }
    let id = NEXT_CONN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    CONNS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((id, w.clone()));
    loop {
        let (rid, req) = match recv::<_, HostMsg>(&mut &conn) {
            Ok(Some(HostMsg::Request { id, req })) => (id, req),
            Ok(Some(HostMsg::Hello { .. })) => continue,
            Ok(None) => break,
            Err(e) => {
                log!("control: bad frame from host: {e}");
                break;
            }
        };
        if let HostReq::Shutdown { timeout_ms } = req {
            let result = shutdown::shutdown(timeout_ms)
                .map(|()| Reply::Done)
                .map_err(|e| GuestError::new(ErrorKind::Io, e));
            write(&w, &GuestMsg::Reply { id: rid, result });
            sys::poweroff();
        }
        let result = handle(rid, req);
        if !write(&w, &GuestMsg::Reply { id: rid, result }) {
            break;
        }
    }
    CONNS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|(i, _)| *i != id);
}

/// Set by `Seal`, cleared by `Restored` (the restore hook).
static SEALED: AtomicBool = AtomicBool::new(false);

fn sealed() -> Result<(), GuestError> {
    if SEALED.load(Ordering::SeqCst) {
        return Err(GuestError::new(
            ErrorKind::InvalidRequest,
            "this VM was snapshotted and the restore hook has not run yet",
        ));
    }
    Ok(())
}

fn set_identity(hostname: &str, machine_id: &str) -> Result<(), GuestError> {
    sys::sethostname(hostname).map_err(io_err("sethostname"))?;
    let hosts = format!("127.0.0.1 localhost\n127.0.1.1 {hostname}\n::1 localhost ip6-localhost\n");
    let id = format!("{machine_id}\n");
    let files = [
        ("/etc/hosts", hosts.as_str()),
        ("/etc/hostname", &format!("{hostname}\n")),
        ("/etc/machine-id", &id),
    ];
    for (path, text) in files {
        if let Err(e) = fs::write(path, text) {
            log!("write {path}: {e}");
        }
    }
    if fs::symlink_metadata("/var/lib/dbus/machine-id").is_ok_and(|m| m.is_file()) {
        let _ = fs::write("/var/lib/dbus/machine-id", &id);
    }
    Ok(())
}

fn io_err(what: &str) -> impl Fn(std::io::Error) -> GuestError + '_ {
    move |e| GuestError::new(ErrorKind::Io, format!("{what}: {e}"))
}

fn handle(id: u64, req: HostReq) -> Result<Reply, GuestError> {
    match req {
        HostReq::Configure {
            hostname,
            rng_seed,
            time_unix_nanos,
            env,
            proxy_port,
            machine_id,
            net_mode,
        } => {
            sealed()?;
            set_identity(&hostname, &machine_id)?;
            sys::add_entropy(&rng_seed).map_err(io_err("rng seed"))?;
            if time_unix_nanos > 0 {
                sys::set_realtime(time_unix_nanos).map_err(io_err("set clock"))?;
            }
            *process::GLOBAL_ENV
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = env;
            netshim::start(proxy_port).map_err(io_err("proxy shim"))?;
            match net_mode {
                pocket_proto::guest::NetMode::Proxy => {}
                pocket_proto::guest::NetMode::Transparent => {
                    crate::netmode::start_transparent().map_err(io_err("transparent networking"))?
                }
                pocket_proto::guest::NetMode::Full => {
                    crate::netmode::start_full().map_err(io_err("network interface"))?
                }
            }
            crate::ports::start_watcher(vec![proxy_port]);
            crate::guestsock::start();
            if process::GLOBAL_ENV
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .any(|(k, v)| k == "SSH_AUTH_SOCK" && v == crate::guestsock::AGENT_SOCK)
            {
                crate::guestsock::start_agent();
            }
            Ok(Reply::Done)
        }
        HostReq::Exec {
            argv,
            env,
            cwd,
            pty,
            user,
        } => sealed()
            .and_then(|()| exec::start(id, &argv, &env, &cwd, pty, user.as_deref()))
            .map(|pid| Reply::ExecStarted { pid }),
        HostReq::SessionCreate {
            name,
            argv,
            env,
            cwd,
            size,
            user,
        } => sealed()
            .and_then(|()| session::create(&name, &argv, &env, &cwd, size, user.as_deref()))
            .map(|pid| Reply::SessionCreated { pid }),
        HostReq::AuthorizeAttach { session, token } => {
            sealed()?;
            session::authorize(&session, token);
            Ok(Reply::Done)
        }
        HostReq::SessionList => Ok(Reply::Sessions(session::list())),
        HostReq::SessionKill { name, signal } => session::kill(&name, signal).map(|()| Reply::Done),
        HostReq::FileRead { path, max_bytes } => {
            let limit = max_bytes.min(MAX_FILE as u64);
            let f = File::open(&path).map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => {
                    GuestError::new(ErrorKind::NotFound, format!("{path}: {e}"))
                }
                _ => GuestError::new(ErrorKind::Io, format!("{path}: {e}")),
            })?;
            let mut data = Vec::new();
            f.take(limit + 1)
                .read_to_end(&mut data)
                .map_err(io_err(&path))?;
            let truncated = data.len() as u64 > limit;
            data.truncate(limit as usize);
            Ok(Reply::File { data, truncated })
        }
        HostReq::FileWrite { path, mode, data } => {
            let tmp = format!("{path}.pocket-tmp");
            let write = || -> std::io::Result<()> {
                let mut f = File::create(&tmp)?;
                f.write_all(&data)?;
                f.set_permissions(fs::Permissions::from_mode(mode))?;
                f.sync_all()?;
                fs::rename(&tmp, &path)
            };
            write().map_err(|e| {
                let _ = fs::remove_file(&tmp);
                io_err(&path)(e)
            })?;
            Ok(Reply::Done)
        }
        HostReq::Restored {
            generation,
            rng_seed,
            time_unix_nanos,
            hostname,
            machine_id,
            clone,
        } => {
            let t0 = sys::boottime_ns();
            sys::add_entropy(&rng_seed).map_err(io_err("rng seed"))?;
            let t1 = sys::boottime_ns();
            sys::set_realtime(time_unix_nanos).map_err(io_err("set clock"))?;
            let t2 = sys::boottime_ns();
            if clone {
                session::forget_all();
                // The source VM's SSH host keys must not be shared by its clones.
                for e in fs::read_dir("/etc/ssh").into_iter().flatten().flatten() {
                    if e.file_name().to_string_lossy().starts_with("ssh_host_") {
                        let _ = fs::remove_file(e.path());
                    }
                }
            }
            let t3 = sys::boottime_ns();
            set_identity(&hostname, &machine_id)?;
            let t4 = sys::boottime_ns();
            crate::ports::REANNOUNCE.store(true, Ordering::SeqCst);
            SEALED.store(false, Ordering::SeqCst);
            log!(
                "restored: generation {generation}{} (rng {} clock {} kill {} identity {} µs)",
                if clone { ", new identity" } else { "" },
                (t1 - t0) / 1000,
                (t2 - t1) / 1000,
                (t3 - t2) / 1000,
                (t4 - t3) / 1000
            );
            Ok(Reply::Done)
        }
        HostReq::Seal => {
            // Copy the identity files up into the overlay now (copy-up fsyncs), so the
            // restore hook only rewrites them.
            let host = fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
            let host = host.trim();
            let mid = fs::read_to_string("/etc/machine-id").unwrap_or_default();
            let mid = mid.trim();
            let mid = if pocket_proto::guest::valid_machine_id(mid) {
                mid.to_string()
            } else {
                "0".repeat(32)
            };
            if pocket_proto::guest::valid_hostname(host) {
                set_identity(host, &mid)?;
            }
            SEALED.store(true, Ordering::SeqCst);
            log!("sealed for a snapshot; waiting for the restore hook");
            Ok(Reply::Done)
        }
        HostReq::Shutdown { .. } => unreachable!("handled by the caller"),
    }
}

pub fn serve_stream(conn: File) {
    let open = match recv::<_, StreamOpen>(&mut &conn) {
        Ok(Some(o)) => o,
        Ok(None) => return,
        Err(e) => {
            let err = GuestError::new(ErrorKind::InvalidRequest, e.to_string());
            let _ = send(&mut &conn, &StreamAck(Err(err)));
            return;
        }
    };
    match open {
        StreamOpen::Attach {
            session,
            size,
            replay_scrollback,
            token,
        } => session::attach(&session, size, replay_scrollback, &token, conn),
        StreamOpen::ExecIo { exec_id } => exec::attach_io(exec_id, conn),
        StreamOpen::GitUploadPack { repo } => git_upload_pack(&repo, conn),
        StreamOpen::PortForward { port } => crate::ports::forward(port, conn),
    }
}

/// Serves `git upload-pack` on a guest repository for a host fetch (`pocket diff`). The
/// host decides what to do with the objects; nothing here runs on the host.
fn git_upload_pack(repo: &str, conn: File) {
    let argv: Vec<String> = [
        "git",
        "-c",
        "safe.directory=*",
        "upload-pack",
        "--strict",
        repo,
    ]
    .map(String::from)
    .to_vec();
    let mut child = match process::spawn(&argv, &[], "/", process::Stdio3::Pipes, None) {
        Ok((c, _status)) => c,
        Err(e) => {
            let _ = send(&mut &conn, &StreamAck(Err(e)));
            return;
        }
    };
    if send(&mut &conn, &StreamAck(Ok(()))).is_err() {
        let _ = child.kill();
        return;
    }
    let (Some(mut stdin), Some(mut stdout)) = (child.stdin.take(), child.stdout.take()) else {
        return;
    };
    drop(child.stderr.take());
    let Ok(mut up) = conn.try_clone() else { return };
    let t = std::thread::spawn(move || {
        let _ = sys::pump(&mut up, &mut stdin);
    });
    let _ = sys::pump(&mut stdout, &conn);
    sys::shutdown_write(&conn);
    let _ = child.kill();
    drop(t);
}
