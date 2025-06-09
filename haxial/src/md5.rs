use bytemuck::{cast_slice, cast_slice_mut};

/// A simple implementation of the MD5 hash algorithm
#[derive(Debug)]
pub struct Md5 {
    state: [u32; 5],
    count: u32,
    buf: [u8; 64],
    buf_len: usize,
}

impl Md5 {
    /// Creates a new MD5 instance
    pub const fn new() -> Self {
        Self {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            count: 0,
            buf: [0; 64],
            buf_len: 0,
        }
    }

    /// Updates the MD5 state with the given input data
    pub fn update(&mut self, input: Option<&[u8]>) {
        if self.buf_len == 64 {
            self.transform(None);
            self.buf_len = 0;
            self.count += 1;
        }

        if let Some(mut data) = input {
            if self.buf_len != 0 {
                while !data.is_empty() && self.buf_len < 64 {
                    self.buf[self.buf_len] = data[0];
                    self.buf_len += 1;
                    data = &data[1..];
                }

                if self.buf_len == 64 {
                    self.transform(None);
                    self.buf_len = 0;
                    self.count += 1;
                }

                if data.is_empty() {
                    return;
                }
            }

            while data.len() >= 64 {
                self.transform(Some(&data[..64]));
                self.buf_len = 0;
                self.count += 1;
                data = &data[64..];
            }

            data.iter().for_each(|&byte| {
                self.buf[self.buf_len] = byte;
                self.buf_len += 1;
            });
        }
    }

    /// Returns the MD5 hash as a 20-byte array
    pub fn report(&mut self) -> [u8; 20] {
        let mut digest = [0u8; 20];
        self.update(None);

        let mut total_bytes = self
            .count
            .wrapping_mul(64)
            .wrapping_add(self.buf_len as u64);
        let total_bits = total_bytes.wrapping_mul(8);

        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 56 {
            self.buf[self.buf_len..64].fill(0);
            self.update(None);
        }

        self.buf[0..56].fill(0);
        self.buf_len = 56;

        let len_hi = (total_bits >> 32) as u32;
        let len_lo = total_bits as u32;

        self.buf[56..60].copy_from_slice(&len_hi.to_be_bytes());
        self.buf[60..64].copy_from_slice(&len_lo.to_be_bytes());

        self.transform(None);

        self.state.iter().enumerate().for_each(|(i, &word)| {
            let bytes = word.to_ne_bytes();
            digest[i << 2..(i << 2) + 4].copy_from_slice(&bytes);
        });

        self.state.fill(0);
        self.buf.fill(0);
        self.count = 0;
        self.buf_len = 0;

        digest
    }

    fn transform(&mut self, block: Option<&[u8]>) {
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let e = self.state[4];

        let block: &[u32] = if let Some(block) = block {
            cast_slice(block)
        } else {
            cast_slice(&self.buf[..])
        };

        let mut x = [0u32; 16];
        x.iter_mut()
            .enumerate()
            .for_each(|(i, x)| *x = block[i].to_be());

        a = ff(a, b, c, d, x[0], 5, 0x5a827999).wrapping_add(e);
        d = ff(d, a, b, c, x[1], 5, 0x5a827999).wrapping_add(e);
        c = ff(c, d, a, b, x[2], 5, 0x5a827999).wrapping_add(e);
        b = ff(b, c, d, a, x[3], 5, 0x5a827999).wrapping_add(e);
        a = ff(a, b, c, d, x[4], 5, 0x5a827999).wrapping_add(e);
        d = ff(d, a, b, c, x[5], 5, 0x5a827999).wrapping_add(e);
        c = ff(c, d, a, b, x[6], 5, 0x5a827999).wrapping_add(e);
        b = ff(b, c, d, a, x[7], 5, 0x5a827999).wrapping_add(e);
        a = ff(a, b, c, d, x[8], 5, 0x5a827999).wrapping_add(e);
        d = ff(d, a, b, c, x[9], 5, 0x5a827999).wrapping_add(e);
        c = ff(c, d, a, b, x[10], 5, 0x5a827999).wrapping_add(e);
        b = ff(b, c, d, a, x[11], 5, 0x5a827999).wrapping_add(e);
        a = ff(a, b, c, d, x[12], 5, 0x5a827999).wrapping_add(e);
        d = ff(d, a, b, c, x[13], 5, 0x5a827999).wrapping_add(e);
        c = ff(c, d, a, b, x[14], 5, 0x5a827999).wrapping_add(e);
        b = ff(b, c, d, a, x[15], 5, 0x5a827999).wrapping_add(e);

        let mut x16 = x[0] ^ x[2] ^ x[8] ^ x[13];
        x16 = x16.rotate_right(31);
        a = ff(a, b, c, d, x16, 5, 0x5a827999).wrapping_add(e);

        let mut x17 = x[1] ^ x[3] ^ x[9] ^ x[14];
        x17 = x17.rotate_right(31);
        d = ff(d, a, b, c, x17, 5, 0x5a827999).wrapping_add(e);

        let mut x18 = x[2] ^ x[4] ^ x[10] ^ x[15];
        x18 = x18.rotate_right(31);
        c = ff(c, d, a, b, x18, 5, 0x5a827999).wrapping_add(e);

        let mut x19 = x[3] ^ x[5] ^ x[11] ^ x16;
        x19 = x19.rotate_right(31);
        b = ff(b, c, d, a, x19, 5, 0x5a827999).wrapping_add(e);

        a = gg(a, b, c, d, x[1], 5, 0x6ed9eba1).wrapping_add(e);
        d = gg(d, a, b, c, x[6], 5, 0x6ed9eba1).wrapping_add(e);
        c = gg(c, d, a, b, x[11], 5, 0x6ed9eba1).wrapping_add(e);
        b = gg(b, c, d, a, x[0], 5, 0x6ed9eba1).wrapping_add(e);
        a = gg(a, b, c, d, x[5], 5, 0x6ed9eba1).wrapping_add(e);
        d = gg(d, a, b, c, x[10], 5, 0x6ed9eba1).wrapping_add(e);
        c = gg(c, d, a, b, x[15], 5, 0x6ed9eba1).wrapping_add(e);
        b = gg(b, c, d, a, x[4], 5, 0x6ed9eba1).wrapping_add(e);
        a = gg(a, b, c, d, x[9], 5, 0x6ed9eba1).wrapping_add(e);
        d = gg(d, a, b, c, x[14], 5, 0x6ed9eba1).wrapping_add(e);
        c = gg(c, d, a, b, x[3], 5, 0x6ed9eba1).wrapping_add(e);
        b = gg(b, c, d, a, x[8], 5, 0x6ed9eba1).wrapping_add(e);
        a = gg(a, b, c, d, x[13], 5, 0x6ed9eba1).wrapping_add(e);
        d = gg(d, a, b, c, x[2], 5, 0x6ed9eba1).wrapping_add(e);
        c = gg(c, d, a, b, x[7], 5, 0x6ed9eba1).wrapping_add(e);
        b = gg(b, c, d, a, x[12], 5, 0x6ed9eba1).wrapping_add(e);

        let mut x20 = x[5] ^ x[7] ^ x[13] ^ x[0];
        x20 = x20.rotate_right(31);
        a = gg(a, b, c, d, x20, 5, 0x6ed9eba1).wrapping_add(e);

        let mut x21 = x[6] ^ x[8] ^ x[14] ^ x[1];
        x21 = x21.rotate_right(31);
        d = gg(d, a, b, c, x21, 5, 0x6ed9eba1).wrapping_add(e);

        let mut x22 = x[7] ^ x[9] ^ x[15] ^ x[2];
        x22 = x22.rotate_right(31);
        c = gg(c, d, a, b, x22, 5, 0x6ed9eba1).wrapping_add(e);

        let mut x23 = x[8] ^ x[10] ^ x[0] ^ x[3];
        x23 = x23.rotate_right(31);
        b = gg(b, c, d, a, x23, 5, 0x6ed9eba1).wrapping_add(e);

        a = hh(a, b, c, d, x[5], 5, 0x8f1bbcdc).wrapping_add(e);
        d = hh(d, a, b, c, x[8], 5, 0x8f1bbcdc).wrapping_add(e);
        c = hh(c, d, a, b, x[11], 5, 0x8f1bbcdc).wrapping_add(e);
        b = hh(b, c, d, a, x[14], 5, 0x8f1bbcdc).wrapping_add(e);
        a = hh(a, b, c, d, x[1], 5, 0x8f1bbcdc).wrapping_add(e);
        d = hh(d, a, b, c, x[4], 5, 0x8f1bbcdc).wrapping_add(e);
        c = hh(c, d, a, b, x[7], 5, 0x8f1bbcdc).wrapping_add(e);
        b = hh(b, c, d, a, x[10], 5, 0x8f1bbcdc).wrapping_add(e);
        a = hh(a, b, c, d, x[13], 5, 0x8f1bbcdc).wrapping_add(e);
        d = hh(d, a, b, c, x[0], 5, 0x8f1bbcdc).wrapping_add(e);
        c = hh(c, d, a, b, x[3], 5, 0x8f1bbcdc).wrapping_add(e);
        b = hh(b, c, d, a, x[6], 5, 0x8f1bbcdc).wrapping_add(e);
        a = hh(a, b, c, d, x[9], 5, 0x8f1bbcdc).wrapping_add(e);
        d = hh(d, a, b, c, x[12], 5, 0x8f1bbcdc).wrapping_add(e);
        c = hh(c, d, a, b, x[15], 5, 0x8f1bbcdc).wrapping_add(e);
        b = hh(b, c, d, a, x[2], 5, 0x8f1bbcdc).wrapping_add(e);

        let mut x24 = x[10] ^ x[12] ^ x[2] ^ x[7];
        x24 = x24.rotate_right(31);
        a = hh(a, b, c, d, x24, 5, 0x8f1bbcdc).wrapping_add(e);

        let mut x25 = x[11] ^ x[13] ^ x[3] ^ x[8];
        x25 = x25.rotate_right(31);
        d = hh(d, a, b, c, x25, 5, 0x8f1bbcdc).wrapping_add(e);

        let mut x26 = x[12] ^ x[14] ^ x[4] ^ x[9];
        x26 = x26.rotate_right(31);
        c = hh(c, d, a, b, x26, 5, 0x8f1bbcdc).wrapping_add(e);

        let mut x27 = x[13] ^ x[15] ^ x[5] ^ x[10];
        x27 = x27.rotate_right(31);
        b = hh(b, c, d, a, x27, 5, 0x8f1bbcdc).wrapping_add(e);

        a = ii(a, b, c, d, x[0], 5, 0xca62c1d6).wrapping_add(e);
        d = ii(d, a, b, c, x[7], 5, 0xca62c1d6).wrapping_add(e);
        c = ii(c, d, a, b, x[14], 5, 0xca62c1d6).wrapping_add(e);
        b = ii(b, c, d, a, x[5], 5, 0xca62c1d6).wrapping_add(e);
        a = ii(a, b, c, d, x[12], 5, 0xca62c1d6).wrapping_add(e);
        d = ii(d, a, b, c, x[3], 5, 0xca62c1d6).wrapping_add(e);
        c = ii(c, d, a, b, x[10], 5, 0xca62c1d6).wrapping_add(e);
        b = ii(b, c, d, a, x[1], 5, 0xca62c1d6).wrapping_add(e);
        a = ii(a, b, c, d, x[8], 5, 0xca62c1d6).wrapping_add(e);
        d = ii(d, a, b, c, x[15], 5, 0xca62c1d6).wrapping_add(e);
        c = ii(c, d, a, b, x[6], 5, 0xca62c1d6).wrapping_add(e);
        b = ii(b, c, d, a, x[13], 5, 0xca62c1d6).wrapping_add(e);
        a = ii(a, b, c, d, x[4], 5, 0xca62c1d6).wrapping_add(e);
        d = ii(d, a, b, c, x[11], 5, 0xca62c1d6).wrapping_add(e);
        c = ii(c, d, a, b, x[2], 5, 0xca62c1d6).wrapping_add(e);
        b = ii(b, c, d, a, x[9], 5, 0xca62c1d6).wrapping_add(e);

        let mut x28 = x[15] ^ x[1] ^ x[7] ^ x[12];
        x28 = x28.rotate_right(31);
        a = ii(a, b, c, d, x28, 5, 0xca62c1d6).wrapping_add(e);

        let mut x29 = x[0] ^ x[2] ^ x[8] ^ x[13];
        x29 = x29.rotate_right(31);
        d = ii(d, a, b, c, x29, 5, 0xca62c1d6).wrapping_add(e);

        let mut x30 = x[1] ^ x[3] ^ x[9] ^ x[14];
        x30 = x30.rotate_right(31);
        c = ii(c, d, a, b, x30, 5, 0xca62c1d6).wrapping_add(e);

        let mut x31 = x[2] ^ x[4] ^ x[10] ^ x[15];
        x31 = x31.rotate_right(31);
        b = ii(b, c, d, a, x31, 5, 0xca62c1d6).wrapping_add(e);

        self.state[0] = self.state[0]
            .wrapping_add(c)
            .wrapping_add((x[9] ^ x[1] ^ x[5] ^ x[12]).rotate_right(31))
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(b ^ d ^ e)
            .wrapping_add(0xca62c1d6);

        self.state[1] = self.state[1].wrapping_add(a);
        self.state[2] = self.state[2].wrapping_add(b.rotate_right(2));
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

const fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

const fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & z) | (y & !z)
}

const fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

const fn i(x: u32, y: u32, z: u32) -> u32 {
    y ^ (x | !z)
}

const fn ff(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32, ac: u32) -> u32 {
    a.wrapping_add(f(b, c, d))
        .wrapping_add(x)
        .wrapping_add(ac)
        .rotate_left(s)
        .wrapping_add(b)
}

const fn gg(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32, ac: u32) -> u32 {
    a.wrapping_add(g(b, c, d))
        .wrapping_add(x)
        .wrapping_add(ac)
        .rotate_left(s)
        .wrapping_add(b)
}

const fn hh(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32, ac: u32) -> u32 {
    a.wrapping_add(h(b, c, d))
        .wrapping_add(x)
        .wrapping_add(ac)
        .rotate_left(s)
        .wrapping_add(b)
}

const fn ii(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32, ac: u32) -> u32 {
    a.wrapping_add(i(b, c, d))
        .wrapping_add(x)
        .wrapping_add(ac)
        .rotate_left(s)
        .wrapping_add(b)
}
