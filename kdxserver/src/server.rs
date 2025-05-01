use chrono::Local;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;

mod chat;
use chat::*;

mod client;
use client::*;

pub struct Server {
	chats: Arc<DashMap<u32, Chat>>,
	clients: Arc<DashMap<u64, Client>>,
	bans: Arc<DashMap<SocketAddr, Ban>>,
}

#[derive(Debug)]
pub struct Ban {
	expires: i64,
	reason: String,
}

impl Ban {
	pub fn new(duration: i64, reason: &str) -> Self {
		Self {
			expires: Local::now().timestamp() + duration,
			reason: reason.to_owned(),
		}
	}
}
