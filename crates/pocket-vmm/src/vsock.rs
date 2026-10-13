use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

/// Longest handshake reply we accept from the VMM (`OK <port>\n`).
const MAX_REPLY: usize = 32;

/// Opens a stream to guest `port` through the VMM's hybrid vsock UDS
/// (`CONNECT <port>\n` → `OK <host port>\n`), the model shared by Cloud Hypervisor and
/// Firecracker.
pub fn connect(uds: &Path, port: u32) -> io::Result<UnixStream> {
    let mut s = UnixStream::connect(uds)?;
    s.write_all(format!("CONNECT {port}\n").as_bytes())?;
    let mut reply = Vec::new();
    let mut b = [0u8; 1];
    // Byte by byte: anything after the newline already belongs to the guest stream.
    loop {
        if s.read(&mut b)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("guest port {port} not accepting connections"),
            ));
        }
        if b[0] == b'\n' {
            break;
        }
        reply.push(b[0]);
        if reply.len() > MAX_REPLY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vsock handshake reply too long",
            ));
        }
    }
    if !reply.starts_with(b"OK ") {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!(
                "vsock handshake rejected: {}",
                String::from_utf8_lossy(&reply)
            ),
        ));
    }
    Ok(s)
}

/// Retries [`connect`] until the guest listens on `port` or `timeout` passes.
pub fn connect_retry(uds: &Path, port: u32, timeout: Duration) -> io::Result<UnixStream> {
    let deadline = Instant::now() + timeout;
    loop {
        match connect(uds, port) {
            Ok(s) => return Ok(s),
            Err(e) if Instant::now() >= deadline => return Err(e),
            Err(_) => std::thread::sleep(Duration::from_micros(500)),
        }
    }
}
