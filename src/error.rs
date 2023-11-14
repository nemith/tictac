use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid packet: {0}")]
    InvalidPacket(String),

    #[error("std::io::Error")]
    StdIoErr(#[from] std::io::Error),
}
