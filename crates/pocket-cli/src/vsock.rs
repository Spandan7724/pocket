//! Direct data streams to a pocket (attach fast path, exec I/O): the VM's hybrid vsock
//! UDS, `CONNECT <port>\n` → `OK <n>\n`, then guest-protocol frames.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use pocket_proto::frame::{recv, send};
use pocket_proto::guest::{STREAM_PORT, StreamAck, StreamOpen};

use crate::error::{CliError, Result};

pub fn open(uds: &Path, open: &StreamOpen) -> Result<UnixStream> {
    let err =
        |e: std::io::Error| CliError::io(&format!("connect to the pocket ({})", uds.display()), e);
    let mut s = UnixStream::connect(uds).map_err(err)?;
    s.write_all(format!("CONNECT {STREAM_PORT}\n").as_bytes())
        .map_err(err)?;
    let mut reply = vec![];
    let mut b = [0u8; 1];
    loop {
        if s.read(&mut b).map_err(err)? == 0 || reply.len() > 32 {
            return Err(CliError::new("guest", 8, "the pocket refused the stream"));
        }
        if b[0] == b'\n' {
            break;
        }
        reply.push(b[0]);
    }
    if !reply.starts_with(b"OK ") {
        return Err(CliError::new("guest", 8, "the pocket refused the stream"));
    }
    send(&mut s, open).map_err(|e| CliError::new("guest", 8, e.to_string()))?;
    match recv::<_, StreamAck>(&mut s) {
        Ok(Some(StreamAck(Ok(())))) => Ok(s),
        Ok(Some(StreamAck(Err(e)))) => Err(CliError::new("guest", 8, e.message)),
        Ok(None) => Err(CliError::new("guest", 8, "the pocket closed the stream")),
        Err(e) => Err(CliError::new("guest", 8, e.to_string())),
    }
}
