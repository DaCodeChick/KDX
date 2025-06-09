use cfg_if::cfg_if;

pub mod algo;
pub use algo::*;

pub mod md5;
pub use md5::*;

pub mod twofish;
pub use twofish::*;

cfg_if! {
    if #[cfg(feature = "net")] {
        pub mod net;
        pub use net::*;
    }
}

/// Errors for cryptographic operations
#[derive(Debug, Error)]
pub enum CryptError {
    #[error("Expected an alignment of {0}, but got {1}")]
    Align(u8, usize),
    #[error("Expected a length of {0}, but got {1}")]
    Length(u8, usize),
}
