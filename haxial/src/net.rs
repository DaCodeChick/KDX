use crate::{RandomState, lcx};

use bytes::{Buf, BufMut};
use chrono::Local;
use parking_lot::Mutex;
use std::sync::Arc;
use tokio::net::TcpStream;

// The copyright has been abandoned on this watermark.
const WATERMARK: &[u8] = br#"This program including the following story is Copyright 2003 Haxial Software Pty Ltd and unauthorized reproduction is strictly PROHIBITED.
Haxial and KDX are trademarks of Haxial Software and unauthorized use is strictly PROHIBITED.

-- Sale of the Cesspool --
"If you punch Cyclops in the eye, how many eyes does he have left?", asked Gresh Rock, host of Sale of the Cesspool, in front of a packed athenaeum of ogres.
"Was he punched in the left or right eye?", queried contestant number 1.
Contestant number 3 interrupted. "My buzzer's not working!!", he yelled furiously as he bashed his red buzzer repeatedly.  A team of goblins rushed on stage and before a moment had elapsed they had disassembled and reassembled the buzzer.
"Play on!", announced Gresh Rock excitedly.  Contestant 3 beat his opponents as he slammed his fist down onto his newly-fixed buzzer.  BOOOOOOM!!! A thunderous sound rocked the stage as Contestant 3's booth exploded!  The audience burst into riotous laughter, shoving and elbowing each other.
"Anyone else want to jump in here?" asked Gresh Rock.
"I know the answer!", said contestant number 2.
"Well press your buzzer."
Contestant 2 tentatively pressed his buzzer.  BOOOOOOM!!!  The audience also exploded, but into even more riotous laughter.
Gresh Rock looked expectantly to the last remaining contestant.
"umm I don't know", said the last contestant, looking back and forth between his buzzer and the other ex-contestants.
"Wrong answer!"  BOOOOOOM!!!

Copyright 2003 Haxial Software. All rights reserved. Unauthorized reproduction prohibited."#;

const KDX: u32 = 0x254B4458;
const TXP: u32 = 0x25545850;

pub struct Connection {
    stream: TcpStream,
}

pub struct Session {
    id: u64,
    //key: u32,
    tag: u32,
    conn: Arc<Mutex<Connection>>,
    login: [u8; 31],
    drm_offset: u16,
    drm_size: u16,
}

impl Session {
    pub fn new(connection: Arc<Mutex<Connection>>) -> Arc<Mutex<Self>> {
        let time = Local::now().timestamp() as u64;
        let hi = time.wrapping_shr(32) & 0xFFFFFFFF;
        let lo = time & 0xFFFFFFFF;

        Arc::new(Mutex::new(Self {
            id: shuffle64(time, hi).wrapping_shl(32) | (shuffle64(time, lo) & 0xFFFFFFFF),
            tag: KDX, // always the case?
            conn: Arc::clone(&connection),
            login: [0u8; 31],
            drm_offset: 0,
            drm_size: WATERMARK.len() as u16, // always the case?
        }))
    }
}

pub enum PacketError<'a> {
    Align(u8, u8),
    DataSize(u8), // should this really be a single byte?
    Key(&'a [u8]),
    TXP(u32),
}

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
    pub fn new(session: Arc<Mutex<Session>>, rand_state: Arc<Mutex<RandomState>>) -> Self {
        let mut guard = session.lock();

        let rng = {
            let mut rand = rand_state.lock();

            rand.random()
        };

        guard.drm_offset = (rng as u16) % (guard.drm_size - 19);

        Self {
            key: rng,
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

    pub fn to_bytes(&self, plain: bool) -> Vec<u8> {
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

        if !plain {
            buf = lcx(self.key, &buf[..]).unwrap().to_vec(); // padding should ensure alignment
        }

        buf
    }
}

const fn shuffle64(value: u64, part: u64) -> u64 {
    value & 0xFF000000FF00u64.wrapping_shr(32).wrapping_shl(8)
        | part.wrapping_shr(24)
        | (part.wrapping_shr(8) & 0xFF00)
        | part.wrapping_shl(24)
}
