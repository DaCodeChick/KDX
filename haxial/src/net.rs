use crate::RandomState;

use chrono::Local;
use parking_lot::Mutex;
use std::sync::Arc;
use tokio::net::TcpStream;

/// The copyright has been abandoned on this watermark.
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

const KDX: u32 = 0x254B4458u32.to_be();
const TXP: u32 = 0x25545850u32.to_be();

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

pub struct PacketHeader {
	key: u32, // The crypt key is not buffered
	txp: u32, // '%TXP', this is where the buffer begins
	tag: u32, // '%KDX' from Session
	drm_offset: u16,
	id: u64,
}

impl PacketHeader {
	pub fn new(session: Arc<Mutex<Session>>, rand_state: Arc<Mutex<RandomState>>) -> Self {
		let mut guard = session.lock();

		let rng = {
			let mut rand = rand_state.lock();

			rand.random()
		};

		guard.drm_offset = (rng as u16) % (guard.drm_size - 19); 

		Self {
			key: rng,
			txp: TXP,
			tag: guard.tag,
			drm_offset: guard.drm_offset.to_be(),
			id: guard.id,
		}
	}
}

const fn shuffle64(value: u64, part: u64) -> u64 {
    value & 0xFF000000FF00u64.wrapping_shr(32).wrapping_shl(8)
        | part.wrapping_shr(24)
        | (part.wrapping_shr(8) & 0xFF00)
        | part.wrapping_shl(24)
}
