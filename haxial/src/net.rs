use crate::{RandomState, lcx};

use bytes::{Buf, BufMut};
use chrono::Local;
use parking_lot::Mutex;
use std::sync::Arc;
use tokio::net::TcpStream;

const KDX: u32 = 0x254B4458;
const TXP: u32 = 0x25545850;

/// Client<->server connection
pub struct Connection {
    stream: TcpStream,
}

/// Client<->server session
pub struct Session<'a> {
    id: u64,
    //key: u32,
    tag: u32,
    conn: Arc<Mutex<Connection>>,
    login: [u8; 31],
	drm: &'a [u8],
    drm_offset: u16,
}

impl Session<'_> {
    /// Establishes a new client<->server session, given a connection.
    pub fn new(connection: Arc<Mutex<Connection>>, drm: &'static [u8]) -> Arc<Mutex<Self>> {
        let time = Local::now().timestamp() as u64;
        let hi = time.wrapping_shr(32) & 0xFFFFFFFF;
        let lo = time & 0xFFFFFFFF;

        Arc::new(Mutex::new(Self {
            id: shuffle64(time, hi).wrapping_shl(32) | (shuffle64(time, lo) & 0xFFFFFFFF),
            tag: KDX, // always the case?
            conn: Arc::clone(&connection),
            login: [0u8; 31],
			drm: drm,
            drm_offset: 0,
        }))
    }
}

pub enum PacketError {
    Align(u8, u8), // expected, got
    DataSize(u8),  // should this really be a single byte?
    TXP(u32),
}

/// A packet of data sent and received between clients
/// and the server
#[derive(Default)]
pub struct Packet {
    key: u32,    // The crypt key is not buffered
    tag: u32,    // '%KDX' from session
    offs0c: u8,  // observed to have a value of 1
    offs0d: u8, // assigned an unknown value from session (field29_0x99 in original Win32 decompilation)
    offs0e: u8, // observed to have a value of 0
    offs10: u32, // observed to have a value of 0
    offs14: u16, // observed to have a value of 0
    drm_offset: u16,
    id: u64,     // session ID
    offs20: u16, // assigned an unknown value from session (field18_0x70 in original Win32 decompilation)
    data: Vec<u8>,
}

impl Packet {
    /// A packet will need data provided by the session and a server-side RNG state.
    pub fn new(session: Arc<Mutex<Session>>, rand_state: Arc<Mutex<RandomState>>) -> Self {
        let mut guard = session.lock();

        let key = {
            let mut rand = rand_state.lock();

            rand.random()
        };

        guard.drm_offset = (key as u16) % ((guard.drm.len() - 19) as u16);

        Self {
            key: key,
            tag: guard.tag,
            drm_offset: guard.drm_offset,
            id: guard.id,
            ..Default::default()
        }
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, PacketError> {
        let mut key = &buf[0..4];
        let key = key.get_u32();
        let buf =
            lcx(key, &buf[4..]).map_err(|_| PacketError::Align(4, (buf[4..].len() & 3) as u8))?;
        let mut buf = &buf[4..];

        let txp = buf.get_u32();
        if txp != TXP {
            return Err(PacketError::TXP(txp));
        }

        let tag = buf.get_u32();
        let offs0c = buf.get_u8();
        let offs0d = buf.get_u8();
        let offs0e = buf.get_u8();

        let data_size = buf.get_u8();
        if (data_size as usize) < buf.remaining() {
            return Err(PacketError::DataSize(data_size));
        }

        Ok(Self {
            key: key,
            tag: tag,
            offs0c: offs0c,
            offs0d: offs0d,
            offs0e: offs0e,
            offs10: buf.get_u32(),
            offs14: buf.get_u16(),
            drm_offset: buf.get_u16(),
            id: buf.get_u64(),
            offs20: buf.get_u16(),
            data: buf.take(data_size as usize).into_inner().to_vec(),
        })
    }

    /// Converts the packet to a byte slice. This does not include
    /// the encryption key.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];

        buf.put_u32(TXP);
        buf.put_u32(self.tag);
        buf.put_u8(self.offs0c);
        buf.put_u8(self.offs0d);
        buf.put_u8(self.offs0e);
        buf.put_u8(self.data.len() as u8);
        buf.put_u32(self.offs10);
        buf.put_u16(self.offs14);
        buf.put_u16(self.drm_offset);
        buf.put_u64(self.id);
        buf.put_u16(self.offs20);
        buf.put(&self.data[..]);

        if buf.len() & 3 != 0 {
            buf.put_bytes(0, buf.len() & 3); // pad to align for encryption
        }

        if cfg!(not(debug_assertions)) {
            buf = lcx(self.key, &buf[..]).unwrap().to_vec(); // padding should ensure alignment
        }

        buf
    }
}

/// Shuffles the bits of a 64-bit value. This is
/// often used for converting timestamps to user IDs.
const fn shuffle64(value: u64, part: u64) -> u64 {
    value & 0xFF000000FF00u64.wrapping_shr(32).wrapping_shl(8)
        | part.wrapping_shr(24)
        | (part.wrapping_shr(8) & 0xFF00)
        | part.wrapping_shl(24)
}
