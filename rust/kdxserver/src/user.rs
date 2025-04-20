use chrono::Local;
use parking_lot::Mutex;
use std::sync::Arc;
use tokio::net::TcpStream;

const KDX: u32 = 0x254B4458;
const TXP: u32 = 0x25545850;

pub struct Connection {
    s: TcpStream,
}

pub struct User<'a> {
    arrival: i64,
    //key: u32,
    tag: u32,
    conn: Arc<Mutex<Connection>>,
    login: [u8; 31],
    drm: &'a [u8],
    drm_offset: u16,
}

impl User<'_> {
    pub fn new(connection: Arc<Mutex<Connection>>, drm: &[u8]) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            arrival: Local::now().timestamp(),
            tag: KDX, // always the case?
            conn: Arc::clone(&connection),
            login: [0u8; 31],
            drm: drm,
            drm_offset: 0,
        }))
    }
}
