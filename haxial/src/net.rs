use chrono::Local;
use parking_lot::Mutex;
use std::sync::Arc;

pub struct Connection {}

pub struct Session {
    id: u64,
    conn: Arc<Mutex<Connection>>,
}

impl Session {
    pub fn new(connection: Arc<Mutex<Connection>>) -> Arc<Mutex<Session>> {
        let time = Local::now().timestamp() as u64;
        let hi = time.wrapping_shr(32) & (u32::MAX as u64);
        let lo = time & (u32::MAX as u64);

        Arc::new(Mutex::new(Session {
            id: shuffle64(time, hi).wrapping_shl(32) | (shuffle64(time, lo) & (u32::MAX as u64)),
            conn: Arc::clone(&connection),
        }))
    }
}

const fn shuffle64(value: u64, part: u64) -> u64 {
    value & 0xFF000000FF00u64.wrapping_shr(32).wrapping_shl(8)
        | part.wrapping_shr(24)
        | (part.wrapping_shr(8) & 0xFF00)
        | part.wrapping_shl(24)
}
