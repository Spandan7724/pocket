//! Network modes besides the env proxy (ARCHITECTURE.md §6).
//!
//! Transparent: a TUN device carries the default route, and nftables redirects every TCP
//! connection to the listener here and every DNS query to the shim here. The listener
//! recovers the original destination and opens a `ProxyOpen::Direct` stream; the shim asks
//! the host (`ProxyOpen::Dns`) and answers with an address from 198.18.0.0/15 that maps back
//! to the name. The host polices both exactly like the proxy; nothing here is a control —
//! with no NIC, a guest that removes the rules simply has no network.
//!
//! Full: the passt NIC, addressed statically.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::Mutex;

use pocket_proto::frame::{recv, send};
use pocket_proto::guest::{DnsReply, PROXY_PORT, ProxyOpen};

use crate::{log, process, sys};

const TRANSPARENT_PORT: u16 = 3129;
const TUN: &str = "pocket0";

fn find(names: &[&str]) -> Option<String> {
    for dir in ["/usr/sbin", "/sbin", "/usr/bin", "/bin"] {
        for n in names {
            let p = format!("{dir}/{n}");
            if std::path::Path::new(&p).exists() {
                return Some(p);
            }
        }
    }
    None
}

/// Runs a tool as root and waits; `Err` with its stderr.
fn run(argv: &[&str], stdin: &[u8]) -> io::Result<()> {
    let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    let (mut child, status) = process::spawn(&argv, &[], "/", process::Stdio3::Pipes, None)
        .map_err(|e| io::Error::other(e.message))?;
    drop(child.stdout.take());
    if let Some(mut i) = child.stdin.take() {
        let _ = i.write_all(stdin);
    }
    let mut err = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut err);
    }
    match status.recv() {
        Ok(pocket_proto::guest::ExitStatus::Code(0)) => Ok(()),
        other => Err(io::Error::other(format!(
            "{} failed ({other:?}): {}",
            argv.join(" "),
            err.trim()
        ))),
    }
}

/// Opens the TUN device and drains it: packets that are not redirected (UDP other than
/// DNS, ICMP) go nowhere.
fn tun() -> io::Result<()> {
    let f = File::options()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;
    // struct ifreq { char name[16]; short flags; ... }
    let mut req = [0u8; 40];
    req[..TUN.len()].copy_from_slice(TUN.as_bytes());
    let flags: libc::c_short = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
    req[16..18].copy_from_slice(&flags.to_ne_bytes());
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    // SAFETY: TUNSETIFF reads an ifreq-sized buffer we own.
    if unsafe { libc::ioctl(f.as_raw_fd(), TUNSETIFF as _, req.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    std::thread::spawn(move || {
        let mut f = f;
        let mut buf = vec![0u8; 65536];
        while f.read(&mut buf).is_ok() {}
    });
    Ok(())
}

const RULES: &str = "table ip pocket {
  chain output {
    type nat hook output priority -100; policy accept;
    ip daddr 127.0.0.0/8 return
    meta l4proto tcp redirect to :3129
    udp dport 53 redirect to :53
  }
}
";

static STARTED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

pub fn start_transparent() -> io::Result<()> {
    if STARTED.get().is_some() {
        return Ok(());
    }
    let ip = find(&["ip"])
        .ok_or_else(|| io::Error::other("transparent mode needs `ip` (iproute2) in the image"))?;
    let nft = find(&["nft"])
        .ok_or_else(|| io::Error::other("transparent mode needs `nft` (nftables) in the image"))?;
    tun()?;
    run(&[&ip, "addr", "add", "10.77.0.2/24", "dev", TUN], b"")?;
    run(&[&ip, "link", "set", TUN, "up"], b"")?;
    run(&[&ip, "route", "replace", "default", "dev", TUN], b"")?;
    std::fs::create_dir_all("/run/pocket")?;
    std::fs::write("/run/pocket/nft.rules", RULES)?;
    run(&[&nft, "-f", "/run/pocket/nft.rules"], b"")?;
    std::fs::write(
        "/etc/resolv.conf",
        "nameserver 127.0.0.1\noptions ndots:0 attempts:2\n",
    )?;
    let tcp = TcpListener::bind((Ipv4Addr::UNSPECIFIED, TRANSPARENT_PORT))?;
    std::thread::spawn(move || {
        for c in tcp.incoming().flatten() {
            std::thread::spawn(move || {
                if let Err(e) = redirected(c) {
                    log!("transparent: {e}");
                }
            });
        }
    });
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 53))?;
    std::thread::spawn(move || dns_loop(udp));
    let _ = STARTED.set(());
    log!("transparent networking: TUN {TUN}, TCP → :{TRANSPARENT_PORT}, DNS → 127.0.0.1:53");
    Ok(())
}

pub fn start_full() -> io::Result<()> {
    if STARTED.set(()).is_err() {
        return Ok(());
    }
    let ip = find(&["ip"])
        .ok_or_else(|| io::Error::other("--net full needs `ip` (iproute2) in the image"))?;
    run(&[&ip, "addr", "add", "10.0.2.15/24", "dev", "eth0"], b"")?;
    run(&[&ip, "link", "set", "eth0", "up"], b"")?;
    run(
        &[&ip, "route", "replace", "default", "via", "10.0.2.2"],
        b"",
    )?;
    std::fs::write("/etc/resolv.conf", "nameserver 10.0.2.3\n")?;
    log!("full networking on eth0 (passt): not filtered by the pocket proxy");
    Ok(())
}

// ---- names ↔ local addresses ------------------------------------------------------------

struct Names {
    by_ip: HashMap<u32, String>,
    by_name: HashMap<String, u32>,
    next: u32,
}

static NAMES: Mutex<Option<Names>> = Mutex::new(None);
const BASE: u32 = u32::from_be_bytes([198, 18, 0, 1]);
const SPAN: u32 = 1 << 17;

fn address_for(name: &str) -> Ipv4Addr {
    let mut g = NAMES.lock().unwrap_or_else(|e| e.into_inner());
    let n = g.get_or_insert_with(|| Names {
        by_ip: HashMap::new(),
        by_name: HashMap::new(),
        next: 0,
    });
    if let Some(&ip) = n.by_name.get(name) {
        return Ipv4Addr::from(ip);
    }
    let ip = BASE + n.next % SPAN;
    n.next += 1;
    if let Some(old) = n.by_ip.insert(ip, name.to_string()) {
        n.by_name.remove(&old);
    }
    n.by_name.insert(name.to_string(), ip);
    Ipv4Addr::from(ip)
}

fn name_of(ip: Ipv4Addr) -> Option<String> {
    let g = NAMES.lock().unwrap_or_else(|e| e.into_inner());
    g.as_ref()?.by_ip.get(&u32::from(ip)).cloned()
}

fn original_dst(s: &TcpStream) -> io::Result<(Ipv4Addr, u16)> {
    const SO_ORIGINAL_DST: libc::c_int = 80;
    let mut a: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `a`.
    let r = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            (&raw mut a).cast(),
            &mut len,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)),
        u16::from_be(a.sin_port),
    ))
}

fn redirected(c: TcpStream) -> io::Result<()> {
    let (ip, port) = original_dst(&c)?;
    let host = name_of(ip).unwrap_or_else(|| ip.to_string());
    crate::netshim::forward_with(
        c,
        ProxyOpen::Direct {
            host,
            port,
            sni: None,
        },
    )
}

// ---- DNS shim -----------------------------------------------------------------------------

fn host_allows(name: &str) -> Result<(), String> {
    let s = sys::vsock_connect(libc::VMADDR_CID_HOST, PROXY_PORT).map_err(|e| e.to_string())?;
    send(&mut &s, &ProxyOpen::Dns { name: name.into() }).map_err(|e| e.to_string())?;
    match recv::<_, DnsReply>(&mut &s) {
        Ok(Some(DnsReply(r))) => r,
        _ => Err("no answer from the host".into()),
    }
}

/// Question name, its end offset and type, from a query.
fn question(q: &[u8]) -> Option<(String, usize, u16)> {
    if q.len() < 12 || u16::from_be_bytes([q[4], q[5]]) != 1 {
        return None;
    }
    let mut i = 12;
    let mut labels = vec![];
    loop {
        let len = *q.get(i)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None;
        }
        labels.push(
            std::str::from_utf8(q.get(i..i + len)?)
                .ok()?
                .to_ascii_lowercase(),
        );
        i += len;
    }
    let qtype = u16::from_be_bytes([*q.get(i)?, *q.get(i + 1)?]);
    Some((labels.join("."), i + 4, qtype))
}

/// `rcode` 0 with an A answer when `addr` is set, else no answers.
fn answer(q: &[u8], end: usize, rcode: u8, addr: Option<Ipv4Addr>) -> Vec<u8> {
    let mut r = q[..end].to_vec();
    r[2] = 0x80 | (q[2] & 0x01); // QR, keep RD
    r[3] = 0x80 | rcode; // RA
    r[6..8].copy_from_slice(&(addr.is_some() as u16).to_be_bytes());
    r[8..12].fill(0);
    if let Some(a) = addr {
        r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 5, 0, 4]);
        r.extend_from_slice(&a.octets());
    }
    r
}

fn dns_loop(udp: UdpSocket) {
    let mut buf = [0u8; 1500];
    loop {
        let Ok((n, from)) = udp.recv_from(&mut buf) else {
            continue;
        };
        let q = buf[..n].to_vec();
        let Ok(sock) = udp.try_clone() else { continue };
        std::thread::spawn(move || {
            let Some((name, end, qtype)) = question(&q) else {
                return;
            };
            let reply = match host_allows(&name) {
                Ok(()) if qtype == 1 => answer(&q, end, 0, Some(address_for(&name))),
                // AAAA and the rest: the name exists, but only IPv4 is routed.
                Ok(()) => answer(&q, end, 0, None),
                Err(_) => answer(&q, end, 3, None),
            };
            let _ = sock.send_to(&reply, from);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_questions_and_answers() {
        // id 0x1234, RD, one question: example.com A IN
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in ["Example", "com"] {
            q.push(l.len() as u8);
            q.extend(l.as_bytes());
        }
        q.extend([0, 0, 1, 0, 1]);
        let (name, end, qtype) = question(&q).unwrap();
        assert_eq!((name.as_str(), end, qtype), ("example.com", q.len(), 1));
        let a = answer(&q, end, 0, Some(address_for("example.com")));
        assert_eq!(&a[..2], &[0x12, 0x34]);
        assert_eq!(a[3] & 0x0f, 0);
        assert_eq!(&a[a.len() - 4..], &[198, 18, 0, 1]);
        assert_eq!(
            name_of(Ipv4Addr::new(198, 18, 0, 1)).as_deref(),
            Some("example.com")
        );
        assert_eq!(address_for("example.com"), Ipv4Addr::new(198, 18, 0, 1));
        let nx = answer(&q, end, 3, None);
        assert_eq!(nx[3] & 0x0f, 3);
        assert!(question(&q[..14]).is_none());
    }
}
