use cfg_if::cfg_if;

pub mod algo;
pub use algo::*;

cfg_if! {
	if #[cfg(feature = "net")] {
		pub mod net;
		pub use net::*;
	}
}
