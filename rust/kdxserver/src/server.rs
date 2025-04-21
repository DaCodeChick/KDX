use chrono::Local;
use std::net::SocketAddr;

mod chat;
use chat::*;

mod user;
use user::*;

#[derive(Debug)]
pub struct Ban {
	expires: i64,
	addr: SocketAddr,
	reason: Vec<u8>,
}

impl Ban {
	pub fn new(addr: SocketAddr, duration: i64, reason: &[u8]) -> Self {
		Self {
			expires: Local::now().timestamp() + duration,
			addr: addr,
			reason: reason.to_vec(),
		}
	}
}
