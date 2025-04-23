use chrono::Local;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

const KDX: u32 = 0x254B4458;
const TXP: u32 = 0x25545850;

pub struct Client {
    arrival: i64,
    //key: u32,
    tag: u32,
    login: [u8; 31],
    drm: &'static [u8],
    drm_offset: u16,
}

pub struct Connection {
	client: Client,
	conn: TcpStream,
	addr: SocketAddr,
}

impl Client {
    pub fn new(drm: &[u8]) -> Self {
        Self {
            arrival: Local::now().timestamp(),
            tag: KDX, // always the case?
            login: [0u8; 31],
            drm: drm,
            drm_offset: 0,
        }
    }
}
