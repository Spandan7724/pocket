//! Frames: `u32` big-endian payload length, then a postcard payload of at most
//! [`MAX_FRAME`] bytes.

use std::io::{self, Read, Write};

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::ProtoError;

pub const MAX_FRAME: usize = 1 << 20;

/// Validation applied to every decoded message before it reaches any other code.
pub trait Validate {
    fn validate(&self) -> Result<(), ProtoError>;
}

pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, ProtoError> {
    let mut out = vec![0u8; 4];
    out = postcard::to_extend(msg, out)?;
    let len = out.len() - 4;
    if len > MAX_FRAME {
        return Err(ProtoError::FrameTooLarge {
            len,
            max: MAX_FRAME,
        });
    }
    out[..4].copy_from_slice(&(len as u32).to_be_bytes());
    Ok(out)
}

/// Decodes one payload (without its length prefix) and validates it.
pub fn decode<T: DeserializeOwned + Validate>(payload: &[u8]) -> Result<T, ProtoError> {
    if payload.len() > MAX_FRAME {
        return Err(ProtoError::FrameTooLarge {
            len: payload.len(),
            max: MAX_FRAME,
        });
    }
    if payload.is_empty() {
        return Err(ProtoError::EmptyFrame);
    }
    let (msg, rest): (T, _) = postcard::take_from_bytes(payload)?;
    if !rest.is_empty() {
        return Err(ProtoError::TrailingBytes(rest.len()));
    }
    msg.validate()?;
    Ok(msg)
}

/// Incremental frame splitter for non-blocking readers. Rejects an oversized length
/// prefix before buffering any of its payload.
#[derive(Default)]
pub struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, ProtoError> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes(self.buf[..4].try_into().unwrap()) as usize;
        if len > MAX_FRAME {
            return Err(ProtoError::FrameTooLarge {
                len,
                max: MAX_FRAME,
            });
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let frame = self.buf[4..4 + len].to_vec();
        self.buf.drain(..4 + len);
        Ok(Some(frame))
    }

    pub fn next_msg<T: DeserializeOwned + Validate>(&mut self) -> Result<Option<T>, ProtoError> {
        self.next_frame()?.map(|f| decode(&f)).transpose()
    }
}

/// Reads one frame payload; `Ok(None)` on a clean EOF before the first byte.
pub fn read_frame<R: Read>(r: &mut R) -> Result<Option<Vec<u8>>, ProtoError> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        match r.read(&mut len[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(ProtoError::Truncated),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(ProtoError::FrameTooLarge {
            len,
            max: MAX_FRAME,
        });
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).map_err(|e| match e.kind() {
        io::ErrorKind::UnexpectedEof => ProtoError::Truncated,
        _ => e.into(),
    })?;
    Ok(Some(payload))
}

pub fn recv<R: Read, T: DeserializeOwned + Validate>(r: &mut R) -> Result<Option<T>, ProtoError> {
    read_frame(r)?.map(|f| decode(&f)).transpose()
}

pub fn send<W: Write, T: Serialize>(w: &mut W, msg: &T) -> Result<(), ProtoError> {
    w.write_all(&encode(msg)?)?;
    Ok(())
}
