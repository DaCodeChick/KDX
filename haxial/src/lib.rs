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
#[derive(Debug)]
pub enum CryptError {
    /// expected, got
    Align(u8, usize),
    /// expected, got
    Length(u8, usize),
}
