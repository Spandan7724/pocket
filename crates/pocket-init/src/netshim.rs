//! Env-proxy mode (ARCHITECTURE.md §6): an HTTP proxy endpoint on guest loopback whose
//! connections are forwarded, unparsed, over vsock to the host proxy, which enforces policy.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::OnceLock;

use pocket_proto::frame::send;
use pocket_proto::guest::{PROXY_PORT, ProxyOpen};

use crate::{log, sys};

static STARTED: OnceLock<u16> = OnceLock::new();

pub fn start(port: u16) -> io::Result<()> {
    if port == 0 || STARTED.get().is_some() {
        return Ok(());
    }
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
    let _ = STARTED.set(port);
    log!("proxy shim listening on 127.0.0.1:{port}");
    std::thread::spawn(move || {
        for c in l.incoming() {
            match c {
                Ok(c) => {
                    std::thread::spawn(move || {
                        if let Err(e) = forward(c) {
                            log!("proxy shim: {e}");
                        }
                    });
                }
                Err(e) => log!("proxy shim accept: {e}"),
            }
        }
    });
    Ok(())
}

fn forward(tcp: TcpStream) -> io::Result<()> {
    tcp.set_nodelay(true)?;
    let host = sys::vsock_connect(libc::VMADDR_CID_HOST, PROXY_PORT)?;
    send(&mut &host, &ProxyOpen::HttpProxy).map_err(io::Error::other)?;
    let (tcp2, host2) = (tcp.try_clone()?, host.try_clone()?);
    let up = std::thread::spawn(move || {
        copy(&tcp2, &host2);
        sys::shutdown_write(&host2);
    });
    copy(&host, &tcp);
    let _ = tcp.shutdown(std::net::Shutdown::Write);
    let _ = up.join();
    Ok(())
}

fn copy(mut from: impl Read, to: impl AsWrite) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if to.write_all_to(&buf[..n]).is_err() {
                    return;
                }
            }
        }
    }
}

trait AsWrite {
    fn write_all_to(&self, b: &[u8]) -> io::Result<()>;
}

impl AsWrite for &File {
    fn write_all_to(&self, b: &[u8]) -> io::Result<()> {
        (&mut &**self).write_all(b)
    }
}

impl AsWrite for &TcpStream {
    fn write_all_to(&self, b: &[u8]) -> io::Result<()> {
        (&mut &**self).write_all(b)
    }
}
