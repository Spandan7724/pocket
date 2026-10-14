//! `pocket-guest`: helper inside a pocket. Invoked as `git-remote-pocket` it is the git
//! remote helper for `pocket://host`, tunnelling `git-upload-pack` to the host over vsock.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::process::ExitCode;

use pocket_proto::frame::send;
use pocket_proto::guest::{GIT_PORT, GitOpen, GitService};

fn vsock_connect(cid: u32, port: u32) -> io::Result<File> {
    // SAFETY: socket/connect on a fresh descriptor owned by the returned File.
    unsafe {
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let f = File::from_raw_fd(fd);
        let mut addr: libc::sockaddr_vm = std::mem::zeroed();
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_cid = cid;
        addr.svm_port = port;
        let r = libc::connect(
            fd,
            (&addr as *const libc::sockaddr_vm).cast(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        );
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(f)
    }
}

fn stdin_raw() -> std::mem::ManuallyDrop<File> {
    // SAFETY: fd 0 stays open for the life of the process; ManuallyDrop never closes it.
    std::mem::ManuallyDrop::new(unsafe { File::from_raw_fd(0) })
}

/// Reads one command line byte by byte, so nothing after it is consumed: once `connect`
/// succeeds the rest of stdin is pack protocol.
fn read_line(f: &mut File) -> io::Result<Option<String>> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        if f.read(&mut b)? == 0 {
            return Ok((!line.is_empty()).then(|| String::from_utf8_lossy(&line).into_owned()));
        }
        if b[0] == b'\n' {
            return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
        }
        line.push(b[0]);
        if line.len() > 4096 {
            return Err(io::Error::other("remote-helper command too long"));
        }
    }
}

/// gitremote-helpers(7) with the `connect` capability only.
fn remote_helper() -> io::Result<ExitCode> {
    let mut input = stdin_raw();
    let mut out = io::stdout().lock();
    while let Some(line) = read_line(&mut input)? {
        match line.as_str() {
            "capabilities" => {
                out.write_all(b"connect\n\n")?;
                out.flush()?;
            }
            "connect git-upload-pack" => {
                let host = vsock_connect(libc::VMADDR_CID_HOST, GIT_PORT)?;
                send(
                    &mut &host,
                    &GitOpen {
                        service: GitService::UploadPack,
                    },
                )
                .map_err(io::Error::other)?;
                out.write_all(b"\n")?;
                out.flush()?;
                drop(out);
                return pipe(host).map(|()| ExitCode::SUCCESS);
            }
            l if l.starts_with("connect ") => {
                eprintln!(
                    "pocket: pushing to the host repository is not possible from inside a pocket; \
                     run `pocket diff` / `pocket apply` on the host instead"
                );
                return Ok(ExitCode::from(128));
            }
            "" => return Ok(ExitCode::SUCCESS),
            other => {
                eprintln!("pocket: unsupported remote-helper command {other:?}");
                return Ok(ExitCode::from(128));
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn pipe(host: File) -> io::Result<()> {
    let mut up = host.try_clone()?;
    let writer = std::thread::spawn(move || -> io::Result<()> {
        let mut stdin = stdin_raw();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = stdin.read(&mut buf)?;
            if n == 0 {
                break;
            }
            up.write_all(&buf[..n])?;
        }
        // SAFETY: shutdown on an open socket.
        unsafe { libc::shutdown(up.as_raw_fd(), libc::SHUT_WR) };
        Ok(())
    });
    let mut down = host;
    let mut stdout = io::stdout().lock();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = down.read(&mut buf)?;
        if n == 0 {
            break;
        }
        stdout.write_all(&buf[..n])?;
        stdout.flush()?;
    }
    drop(stdout);
    let _ = writer.join();
    Ok(())
}

fn main() -> ExitCode {
    let argv0 = std::env::args().next().unwrap_or_default();
    let name = argv0.rsplit('/').next().unwrap_or_default();
    let result = match name {
        "git-remote-pocket" => remote_helper(),
        _ => {
            eprintln!("usage: invoked by git as git-remote-pocket (pocket://host remotes)");
            Ok(ExitCode::from(2))
        }
    };
    result.unwrap_or_else(|e| {
        eprintln!("pocket-guest: {e}");
        ExitCode::from(128)
    })
}
