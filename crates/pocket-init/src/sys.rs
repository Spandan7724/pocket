//! Thin wrappers over the handful of syscalls PID 1 needs.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::sync::Mutex;

use pocket_proto::guest::PtySize;

pub fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

pub fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in string"))
}

/// `mount(2)` without added context, so `raw_os_error()` survives.
pub fn mount_raw(
    src: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> io::Result<()> {
    let (s, t, f) = (cstr(src)?, cstr(target)?, cstr(fstype)?);
    let d = data.map(cstr).transpose()?;
    // SAFETY: valid C strings that outlive the call.
    cvt(unsafe {
        libc::mount(
            s.as_ptr(),
            t.as_ptr(),
            f.as_ptr(),
            flags,
            d.as_ref().map_or(std::ptr::null(), |d| d.as_ptr().cast()),
        )
    })
    .map(drop)
}

pub fn mount(
    src: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> io::Result<()> {
    mount_raw(src, target, fstype, flags, data)
        .map_err(|e| io::Error::new(e.kind(), format!("mount {fstype} {src} on {target}: {e}")))
}

pub fn move_mount(from: &str, to: &str) -> io::Result<()> {
    mount(from, to, "", libc::MS_MOVE, None)
}

pub fn bind_mount(from: &str, to: &str) -> io::Result<()> {
    mount(from, to, "", libc::MS_BIND, None)
}

pub fn umount(target: &str) -> io::Result<()> {
    let t = cstr(target)?;
    // SAFETY: valid C string.
    cvt(unsafe { libc::umount2(t.as_ptr(), 0) })
        .map(drop)
        .map_err(|e| io::Error::new(e.kind(), format!("umount {target}: {e}")))
}

pub fn pivot_root(new_root: &str, put_old: &str) -> io::Result<()> {
    let (n, o) = (cstr(new_root)?, cstr(put_old)?);
    // SAFETY: raw syscall with two valid C strings.
    let r = unsafe { libc::syscall(libc::SYS_pivot_root, n.as_ptr(), o.as_ptr()) };
    cvt(r as libc::c_int).map(drop)
}

pub fn sethostname(name: &str) -> io::Result<()> {
    // SAFETY: pointer/length pair from a live &str.
    cvt(unsafe { libc::sethostname(name.as_ptr().cast(), name.len()) }).map(drop)
}

pub fn boottime_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: writes into a local timespec.
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

pub fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

pub fn set_realtime(nanos: u128) -> io::Result<()> {
    let ts = libc::timespec {
        tv_sec: (nanos / 1_000_000_000) as libc::time_t,
        tv_nsec: (nanos % 1_000_000_000) as libc::c_long,
    };
    // SAFETY: reads a local timespec.
    cvt(unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) }).map(drop)
}

static KMSG: Mutex<Option<File>> = Mutex::new(None);

/// Logs to the kernel ring buffer (visible on the serial console when enabled).
pub fn log(msg: &str) {
    log_at(6, msg)
}

pub fn log_at(level: u8, msg: &str) {
    let mut k = KMSG.lock().unwrap_or_else(|e| e.into_inner());
    if k.is_none() {
        *k = File::options().write(true).open("/dev/kmsg").ok();
    }
    if let Some(f) = k.as_mut() {
        let _ = f.write_all(format!("<{level}>pocket-init: {msg}\n").as_bytes());
    }
}

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => { $crate::sys::log(&format!($($arg)*)) };
}

pub fn poweroff() -> ! {
    // SAFETY: plain syscalls.
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_POWER_OFF);
    }
    loop {
        std::thread::park();
    }
}

pub fn vsock_listen(port: u32) -> io::Result<File> {
    // SAFETY: socket/bind/listen on a fresh descriptor owned by the returned File.
    unsafe {
        let fd = cvt(libc::socket(
            libc::AF_VSOCK,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
        ))?;
        let f = File::from_raw_fd(fd);
        let mut addr: libc::sockaddr_vm = std::mem::zeroed();
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_cid = libc::VMADDR_CID_ANY;
        addr.svm_port = port;
        cvt(libc::bind(
            fd,
            (&addr as *const libc::sockaddr_vm).cast(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        ))?;
        cvt(libc::listen(fd, 64))?;
        Ok(f)
    }
}

pub fn accept(listener: &File) -> io::Result<File> {
    loop {
        // SAFETY: accept on a listening socket; the new fd is owned by the File.
        let r = unsafe {
            libc::accept4(
                listener.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        match cvt(r) {
            Ok(fd) => return Ok(unsafe { File::from_raw_fd(fd) }),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

pub fn shutdown_write(f: &File) {
    // SAFETY: shutdown on an open socket.
    unsafe { libc::shutdown(f.as_raw_fd(), libc::SHUT_WR) };
}

pub fn set_winsize(fd: RawFd, size: PtySize) -> io::Result<()> {
    let ws = libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCSWINSZ reads a local winsize.
    cvt(unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) }).map(drop)
}

/// Returns (master, slave); both close-on-exec.
pub fn openpty(size: PtySize) -> io::Result<(File, File)> {
    // SAFETY: standard posix_openpt sequence; every fd ends up owned by a File.
    unsafe {
        let m = cvt(libc::posix_openpt(
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        ))?;
        let master = File::from_raw_fd(m);
        cvt(libc::grantpt(m))?;
        cvt(libc::unlockpt(m))?;
        let mut name = [0 as libc::c_char; 64];
        if libc::ptsname_r(m, name.as_mut_ptr(), name.len()) != 0 {
            return Err(io::Error::last_os_error());
        }
        let s = cvt(libc::open(
            name.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        ))?;
        let slave = File::from_raw_fd(s);
        set_winsize(m, size)?;
        Ok((master, slave))
    }
}

pub fn kill(pid: i32, sig: i32) -> io::Result<()> {
    // SAFETY: plain syscall.
    cvt(unsafe { libc::kill(pid, sig) }).map(drop)
}

pub const HANDLED_SIGNALS: [libc::c_int; 5] = [
    libc::SIGCHLD,
    libc::SIGTERM,
    libc::SIGINT,
    libc::SIGHUP,
    libc::SIGPWR,
];

pub fn handled_sigset() -> libc::sigset_t {
    // SAFETY: initialises a local sigset.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for s in HANDLED_SIGNALS {
            libc::sigaddset(&mut set, s);
        }
        set
    }
}

/// Blocks the signals the signal thread consumes; threads spawned later inherit the mask.
pub fn block_handled_signals() {
    let set = handled_sigset();
    // SAFETY: valid sigset pointer.
    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
}

/// For `pre_exec`: children start with an empty mask (async-signal-safe).
pub fn unblock_all_signals() -> io::Result<()> {
    // SAFETY: async-signal-safe calls on a local sigset.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        cvt(libc::sigprocmask(
            libc::SIG_SETMASK,
            &set,
            std::ptr::null_mut(),
        ))
        .map(drop)
    }
}

pub fn wait_signal() -> libc::c_int {
    let set = handled_sigset();
    loop {
        // SAFETY: valid sigset; null siginfo is allowed.
        let s = unsafe { libc::sigwaitinfo(&set, std::ptr::null_mut()) };
        if s > 0 {
            return s;
        }
    }
}

const RNDADDENTROPY: libc::c_ulong = 0x4008_5203;
const RNDRESEEDCRNG: libc::c_ulong = 0x5207;

/// Mixes `seed` into the kernel pool, credits it, and forces a CRNG reseed.
pub fn add_entropy(seed: &[u8]) -> io::Result<()> {
    let f = File::options().write(true).open("/dev/random")?;
    // struct rand_pool_info { int entropy_count; int buf_size; __u32 buf[]; }
    let mut info = Vec::with_capacity(8 + seed.len());
    info.extend_from_slice(&((seed.len() * 8) as i32).to_ne_bytes());
    info.extend_from_slice(&(seed.len() as i32).to_ne_bytes());
    info.extend_from_slice(seed);
    info.resize(8 + seed.len().div_ceil(4) * 4, 0);
    // SAFETY: the buffer matches rand_pool_info's layout and outlives both ioctls.
    unsafe {
        cvt(libc::ioctl(
            f.as_raw_fd(),
            RNDADDENTROPY as _,
            info.as_ptr(),
        ))?;
        cvt(libc::ioctl(f.as_raw_fd(), RNDRESEEDCRNG as _, 0))?;
    }
    Ok(())
}

pub fn getpid() -> i32 {
    // SAFETY: plain syscall.
    unsafe { libc::getpid() }
}

pub fn vsock_connect(cid: u32, port: u32) -> io::Result<File> {
    // SAFETY: socket/connect on a fresh descriptor owned by the returned File.
    unsafe {
        let fd = cvt(libc::socket(
            libc::AF_VSOCK,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
        ))?;
        let f = File::from_raw_fd(fd);
        let mut addr: libc::sockaddr_vm = std::mem::zeroed();
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_cid = cid;
        addr.svm_port = port;
        cvt(libc::connect(
            fd,
            (&addr as *const libc::sockaddr_vm).cast(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        ))?;
        Ok(f)
    }
}

/// Brings up `lo` (the guest has no other interface).
pub fn loopback_up() -> io::Result<()> {
    // SAFETY: ioctls on a local ifreq through a fresh socket owned by a File.
    unsafe {
        let fd = cvt(libc::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            0,
        ))?;
        let _sock = File::from_raw_fd(fd);
        let mut ifr: libc::ifreq = std::mem::zeroed();
        for (i, b) in b"lo".iter().enumerate() {
            ifr.ifr_name[i] = *b as libc::c_char;
        }
        cvt(libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &mut ifr))?;
        ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
        cvt(libc::ioctl(fd, libc::SIOCSIFFLAGS as _, &ifr))?;
    }
    Ok(())
}

pub fn lchown(path: &std::path::Path, uid: u32, gid: u32) -> io::Result<()> {
    std::os::unix::fs::lchown(path, Some(uid), Some(gid))
}

pub fn fchown(f: &File, uid: u32, gid: u32) -> io::Result<()> {
    // SAFETY: fchown on an open descriptor.
    cvt(unsafe { libc::fchown(f.as_raw_fd(), uid, gid) }).map(drop)
}

/// Constant-time comparison for secrets.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
