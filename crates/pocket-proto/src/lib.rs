//! Wire types shared by the CLI, the daemon and the guest.
//!
//! [`guest`] is the host↔guest vsock protocol (CONTRACTS.md §3); [`frame`] its framing.
//! Everything decoded on the host from a guest is hostile: use [`frame::decode`] (or
//! [`frame::FrameReader`]), which size-limits, rejects trailing bytes and validates.

pub mod frame;
pub mod guest;

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("frame of {len} bytes exceeds the {max} byte limit")]
    FrameTooLarge { len: usize, max: usize },
    #[error("empty frame")]
    EmptyFrame,
    #[error("malformed message: {0}")]
    Decode(#[from] postcard::Error),
    #[error("{0} trailing bytes after message")]
    TrailingBytes(usize),
    #[error("invalid message: {0}")]
    Invalid(String),
    #[error("connection closed mid-frame")]
    Truncated,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub(crate) fn invalid(msg: impl Into<String>) -> ProtoError {
    ProtoError::Invalid(msg.into())
}
