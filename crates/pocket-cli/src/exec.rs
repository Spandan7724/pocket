//! `pocket exec`: one-shot command over the `ExecIo` stream; stdio streamed, signals
//! forwarded, the guest's exit status becomes ours.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex};

use pocket_proto::frame::{recv, send};
use pocket_proto::guest::{ExecIn, ExecOut, MAX_CHUNK, PtySize, StreamOpen};

use crate::error::{CliError, Result};
use crate::term::{self, RawGuard};
use crate::vsock;

pub fn run(uds: &Path, exec_id: u64, tty: bool) -> Result<u8> {
    let stream = vsock::open(uds, &StreamOpen::ExecIo { exec_id })?;
    let w = Arc::new(Mutex::new(
        stream.try_clone().map_err(|e| CliError::io("exec", e))?,
    ));
    let _guard = if tty && term::is_tty(0) {
        Some(RawGuard::enter().map_err(|e| CliError::io("set raw mode", e))?)
    } else {
        None
    };
    // Signals go to the guest process instead of killing us.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: building and applying a local signal mask before spawning threads.
    unsafe {
        libc::sigemptyset(&mut set);
        for s in [
            libc::SIGINT,
            libc::SIGTERM,
            libc::SIGHUP,
            libc::SIGWINCH,
            libc::SIGQUIT,
        ] {
            libc::sigaddset(&mut set, s);
        }
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
    let w2 = w.clone();
    std::thread::spawn(move || {
        loop {
            let mut sig = 0;
            // SAFETY: sigwait on the mask built above.
            if unsafe { libc::sigwait(&set, &mut sig) } != 0 {
                return;
            }
            let msg = if sig == libc::SIGWINCH {
                let (rows, cols) = term::size();
                ExecIn::Resize(PtySize { rows, cols })
            } else {
                ExecIn::Signal(sig)
            };
            if send(&mut *w2.lock().unwrap(), &msg).is_err() {
                return;
            }
        }
    });
    let forward_stdin = tty || !term::is_tty(0);
    if forward_stdin {
        let w3 = w.clone();
        std::thread::spawn(move || {
            let mut stdin = std::io::stdin().lock();
            let mut buf = vec![0u8; MAX_CHUNK];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) | Err(_) => {
                        let _ = send(&mut *w3.lock().unwrap(), &ExecIn::CloseStdin);
                        return;
                    }
                    Ok(n) => {
                        if send(&mut *w3.lock().unwrap(), &ExecIn::Stdin(buf[..n].to_vec()))
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            }
        });
    } else {
        let _ = send(&mut *w.lock().unwrap(), &ExecIn::CloseStdin);
    }
    let mut r: UnixStream = stream;
    let (mut out, mut err) = (std::io::stdout().lock(), std::io::stderr().lock());
    loop {
        match recv::<_, ExecOut>(&mut r) {
            Ok(Some(ExecOut::Stdout(d))) => {
                let _ = out.write_all(&d);
                let _ = out.flush();
            }
            Ok(Some(ExecOut::Stderr(d))) => {
                let _ = err.write_all(&d);
                let _ = err.flush();
            }
            Ok(Some(ExecOut::Exited(st))) => return Ok(st.code().clamp(0, 255) as u8),
            Ok(None) => {
                return Err(CliError::new(
                    "guest",
                    8,
                    "the pocket closed the exec stream before the command exited",
                ));
            }
            Err(e) => return Err(CliError::new("guest", 8, format!("exec stream: {e}"))),
        }
    }
}
