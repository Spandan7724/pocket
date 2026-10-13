//! Exec service: `Exec` starts the process; the host then opens `StreamOpen::ExecIo` to
//! stream stdin/stdout/stderr and receive the exit status. Output waits in the pipes
//! (back-pressuring the child) until the stream is attached.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::sync::Mutex;
use std::sync::mpsc::Receiver;

use pocket_proto::frame::{recv, send};
use pocket_proto::guest::{ErrorKind, ExecIn, ExecOut, ExitStatus, GuestError, PtySize};

use crate::process::{Stdio3, spawn};
use crate::{log, sys};

const CHUNK: usize = 32 * 1024;

struct Entry {
    pid: i32,
    stdin: Option<File>,
    outputs: Vec<(File, bool)>, // (fd, is_stderr)
    pty: Option<File>,
    status: Receiver<ExitStatus>,
}

static EXECS: Mutex<Option<HashMap<u64, Entry>>> = Mutex::new(None);

pub fn start(
    id: u64,
    argv: &[String],
    env: &[(String, String)],
    cwd: &str,
    pty: Option<PtySize>,
) -> Result<u32, GuestError> {
    let io = |e: std::io::Error| GuestError::new(ErrorKind::Io, e.to_string());
    let mut execs = EXECS.lock().unwrap_or_else(|e| e.into_inner());
    let map = execs.get_or_insert_with(HashMap::new);
    if map.contains_key(&id) {
        return Err(GuestError::new(
            ErrorKind::AlreadyExists,
            format!("exec id {id} in use"),
        ));
    }
    let entry = match pty {
        Some(size) => {
            let (master, slave) = sys::openpty(size).map_err(io)?;
            let (child, status) = spawn(argv, env, cwd, Stdio3::Pty(slave))?;
            Entry {
                pid: child.id() as i32,
                stdin: None,
                outputs: vec![(master.try_clone().map_err(io)?, false)],
                pty: Some(master),
                status,
            }
        }
        None => {
            let (mut child, status) = spawn(argv, env, cwd, Stdio3::Pipes)?;
            let out = File::from(std::os::fd::OwnedFd::from(child.stdout.take().unwrap()));
            let err = File::from(std::os::fd::OwnedFd::from(child.stderr.take().unwrap()));
            let stdin = File::from(std::os::fd::OwnedFd::from(child.stdin.take().unwrap()));
            Entry {
                pid: child.id() as i32,
                stdin: Some(stdin),
                outputs: vec![(out, false), (err, true)],
                pty: None,
                status,
            }
        }
    };
    let pid = entry.pid as u32;
    map.insert(id, entry);
    Ok(pid)
}

fn take(id: u64) -> Option<Entry> {
    EXECS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_mut()?
        .remove(&id)
}

/// Serves an `ExecIo` stream. The `StreamAck` has not been sent yet.
pub fn attach_io(id: u64, conn: File) {
    let Some(mut e) = take(id) else {
        let err = GuestError::new(ErrorKind::NotFound, format!("no pending exec {id}"));
        let _ = send(&mut &conn, &pocket_proto::guest::StreamAck(Err(err)));
        return;
    };
    if send(&mut &conn, &pocket_proto::guest::StreamAck(Ok(()))).is_err() {
        return;
    }
    let Ok(out_conn) = conn.try_clone() else {
        return;
    };
    let outputs = std::mem::take(&mut e.outputs);
    let status = e.status;
    let pump = std::thread::spawn(move || pump_output(outputs, status, out_conn));

    let mut stdin = e.stdin.take();
    let input = e.pty.as_ref().and_then(|p| p.try_clone().ok());
    loop {
        let msg = match recv::<_, ExecIn>(&mut &conn) {
            Ok(Some(m)) => m,
            Ok(None) => break,
            Err(err) => {
                log!("exec {id}: bad frame from host: {err}");
                break;
            }
        };
        match msg {
            ExecIn::Stdin(data) => {
                let res = match (&mut stdin, &input) {
                    (Some(w), _) => w.write_all(&data),
                    (None, Some(pty)) => (&mut &*pty).write_all(&data),
                    (None, None) => Ok(()),
                };
                if let Err(err) = res {
                    log!("exec {id}: stdin write: {err}");
                }
            }
            ExecIn::CloseStdin => stdin = None,
            ExecIn::Signal(sig) => {
                let _ = sys::kill(e.pid, sig);
            }
            ExecIn::Resize(size) => {
                if let Some(p) = &e.pty {
                    let _ = sys::set_winsize(p.as_raw_fd(), size);
                }
            }
        }
    }
    drop(stdin);
    let _ = pump.join();
}

fn pump_output(mut outputs: Vec<(File, bool)>, status: Receiver<ExitStatus>, conn: File) {
    let mut buf = vec![0u8; CHUNK];
    while !outputs.is_empty() {
        let mut fds: Vec<libc::pollfd> = outputs
            .iter()
            .map(|(f, _)| libc::pollfd {
                fd: f.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        // SAFETY: fds points to a live Vec of pollfd.
        let r = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if r < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        let mut closed = vec![];
        for (i, p) in fds.iter().enumerate() {
            if p.revents == 0 {
                continue;
            }
            let (f, is_err) = &mut outputs[i];
            match f.read(&mut buf) {
                Ok(0) | Err(_) => closed.push(i), // EIO on a pty master = all slaves closed
                Ok(n) => {
                    let data = buf[..n].to_vec();
                    let msg = if *is_err {
                        ExecOut::Stderr(data)
                    } else {
                        ExecOut::Stdout(data)
                    };
                    if send(&mut &conn, &msg).is_err() {
                        return;
                    }
                }
            }
        }
        for i in closed.into_iter().rev() {
            outputs.remove(i);
        }
    }
    if let Ok(st) = status.recv() {
        let _ = send(&mut &conn, &ExecOut::Exited(st));
    }
    sys::shutdown_write(&conn);
}
