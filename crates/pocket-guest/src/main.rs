//! `pocket-guest`: helper inside a pocket. Invoked as `git-remote-pocket` it is the git
//! remote helper for `pocket://host`, tunnelling `git-upload-pack` to the host over vsock.
//! As `xdg-open` (and friends) it opens http(s) URLs in the host browser; as `xclip` /
//! `wl-paste` it serves images pasted from the host (`pocket attach` uploads them) and turns
//! clipboard writes into OSC 52; `pocket-guest notify|allow|open` talk to the host.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::process::ExitCode;

use pocket_proto::frame::send;
use pocket_proto::guest::{ApprovalKind, GIT_PORT, GitOpen, GitService, GuestEvent};

const GUEST_SOCK: &str = "/run/pocket/guest.sock";
const PASTE: &str = "/tmp/pocket-paste/latest.png";
/// A pasted image is offered to clipboard readers for this long.
const PASTE_FRESH: std::time::Duration = std::time::Duration::from_secs(120);

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
    // Not joined: once the host side closes, returning from main ends the stdin reader.
    std::thread::spawn(move || -> io::Result<()> {
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
    Ok(())
}

fn to_host(ev: GuestEvent) -> io::Result<()> {
    let s = std::os::unix::net::UnixStream::connect(GUEST_SOCK)
        .map_err(|e| io::Error::new(e.kind(), format!("{GUEST_SOCK}: {e}")))?;
    send(&mut &s, &ev).map_err(io::Error::other)
}

fn open(args: &[String]) -> io::Result<ExitCode> {
    let Some(url) = args.iter().find(|a| !a.starts_with('-')) else {
        eprintln!("usage: pocket-guest open URL");
        return Ok(ExitCode::from(2));
    };
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        eprintln!("pocket: only http(s) URLs open on the host, not {url:?}");
        return Ok(ExitCode::from(1));
    }
    to_host(GuestEvent::OpenUrl { url: url.clone() })?;
    eprintln!("pocket: asked the host to open {url}");
    Ok(ExitCode::SUCCESS)
}

fn notify(args: &[String]) -> io::Result<ExitCode> {
    let mut title = String::from("pocket");
    let mut body = vec![];
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--title" | "-t" => title = it.next().cloned().unwrap_or_default(),
            _ => body.push(a.clone()),
        }
    }
    to_host(GuestEvent::Notify {
        session: None,
        title,
        body: body.join(" "),
    })?;
    Ok(ExitCode::SUCCESS)
}

fn allow(args: &[String]) -> io::Result<ExitCode> {
    let Some(target) = args.first() else {
        eprintln!("usage: pocket-guest allow HOST[:PORT]");
        return Ok(ExitCode::from(2));
    };
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(p) => (h.to_string(), Some(p)),
            Err(_) => (target.clone(), None),
        },
        None => (target.clone(), None),
    };
    to_host(GuestEvent::ApprovalRequest {
        kind: ApprovalKind::Host {
            host: host.to_ascii_lowercase(),
            port,
        },
    })?;
    eprintln!("pocket: asked the user to allow {target}; retry once they approve");
    Ok(ExitCode::SUCCESS)
}

fn request_file(args: &[String]) -> io::Result<ExitCode> {
    let Some(path) = args.first().filter(|p| p.starts_with('/')) else {
        eprintln!("usage: pocket-guest request-file /ABSOLUTE/HOST/PATH");
        return Ok(ExitCode::from(2));
    };
    to_host(GuestEvent::ApprovalRequest {
        kind: ApprovalKind::File { path: path.clone() },
    })?;
    let name = path.rsplit('/').next().unwrap_or("file");
    eprintln!(
        "pocket: asked the user for {path}; once approved it appears as /tmp/pocket-files/{name}"
    );
    Ok(ExitCode::SUCCESS)
}

fn b64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn fresh_paste() -> bool {
    std::fs::metadata(PASTE)
        .and_then(|m| m.modified())
        .is_ok_and(|t| t.elapsed().is_ok_and(|e| e < PASTE_FRESH))
}

/// Clipboard writes become OSC 52 on the controlling terminal (the host decides).
fn copy_to_host() -> io::Result<ExitCode> {
    let mut data = Vec::new();
    io::stdin().read_to_end(&mut data)?;
    let mut tty = std::fs::OpenOptions::new().write(true).open("/dev/tty")?;
    write!(tty, "\x1b]52;c;{}\x07", b64(&data))?;
    Ok(ExitCode::SUCCESS)
}

/// `xclip` / `wl-paste` / `wl-copy` subset: image reads come from the last host paste.
fn clipboard(tool: &str, args: &[String]) -> io::Result<ExitCode> {
    let has = |f: &[&str]| args.iter().any(|a| f.contains(&a.as_str()));
    let value = |f: &[&str]| {
        args.iter()
            .position(|a| f.contains(&a.as_str()))
            .and_then(|i| args.get(i + 1))
            .map(String::as_str)
    };
    let (reading, ty) = match tool {
        "wl-copy" => (false, None),
        "wl-paste" => {
            if has(&["--list-types", "-l"]) {
                (true, Some("TARGETS"))
            } else {
                (true, value(&["--type", "-t"]))
            }
        }
        _ => (has(&["-o", "-out"]), value(&["-t", "-target"])),
    };
    if !reading {
        return copy_to_host();
    }
    match ty {
        Some("TARGETS") => {
            if fresh_paste() {
                println!("image/png");
                return Ok(ExitCode::SUCCESS);
            }
        }
        Some(t) if t.starts_with("image/") && fresh_paste() => {
            let data = std::fs::read(PASTE)?;
            io::stdout().write_all(&data)?;
            return Ok(ExitCode::SUCCESS);
        }
        _ => {}
    }
    eprintln!(
        "pocket: the host clipboard is not readable from a pocket (images pasted with Ctrl-V in `pocket attach` are)"
    );
    Ok(ExitCode::from(1))
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let argv0 = argv.first().cloned().unwrap_or_default();
    let name = argv0.rsplit('/').next().unwrap_or_default();
    let rest = &argv[1.min(argv.len())..];
    let result = match name {
        "git-remote-pocket" => remote_helper(),
        "xdg-open" | "sensible-browser" | "x-www-browser" => open(rest),
        "xclip" | "wl-paste" | "wl-copy" => clipboard(name, rest),
        _ => match rest.first().map(String::as_str) {
            Some("open") => open(&rest[1..]),
            Some("notify") => notify(&rest[1..]),
            Some("allow") => allow(&rest[1..]),
            Some("request-file") => request_file(&rest[1..]),
            _ => {
                eprintln!(
                    "usage: pocket-guest open URL | notify [--title T] TEXT | allow HOST[:PORT] | request-file PATH"
                );
                Ok(ExitCode::from(2))
            }
        },
    };
    result.unwrap_or_else(|e| {
        eprintln!("pocket-guest: {e}");
        ExitCode::from(128)
    })
}
