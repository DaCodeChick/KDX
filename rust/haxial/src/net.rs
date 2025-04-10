use crate::tcp_packet_crypt;

use bytes::{Buf, BufMut};

pub const KDX: u32 = 0x254B4458;
pub const TXP: u32 = 0x25545850;

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
    pub fn from_bytes(buf: &[u8]) -> Result<Self, PacketError> {
        let mut key = &buf[0..4];
        let key = key.get_u32();
        let buf = tcp_packet_crypt(key, &buf[4..])
            .map_err(|_| PacketError::Align(4, (buf[4..].len() & 3) as u8))?;
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

        buf = tcp_packet_crypt(self.key, &buf[..]).unwrap().to_vec(); // padding should ensure alignment

        buf
    }
}
