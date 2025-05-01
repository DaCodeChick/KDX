/// A simple MD5 implementation
#[derive(Debug)]
pub struct Md5 {
    state: [u32; 4],
    count: [u32; 2],
    buf: [u8; 64],
    buf_len: usize,
}

impl Md5 {
    /// Creates a new MD5 instance
    pub fn new() -> Self {
        Self {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476],
            count: [0xC3D2E1F0, 0],
            buf: [0; 64],
            buf_len: 0,
        }
    }

    /// Updates the MD5 state with the given input data
    pub fn update(&mut self, input: Option<&[u8]>) {
        if self.buf_len == 64 {
            self.transform(None);
            self.buf_len = 0;
            self.count[1] = self.count[1].wrapping_add(1);
        }

        if let Some(mut data) = input {
            if self.buf_len > 0 {
                while !data.is_empty() && self.buf_len < 64 {
                    self.buf[self.buf_len] = data[0];
                    self.buf_len += 1;
                    data = &data[1..];
                }

                if self.buf_len == 64 {
                    self.transform(None);
                    self.buf_len = 0;
                    self.count[1] = self.count[1].wrapping_add(1);
                }

                if data.is_empty() {
                    return;
                }
            }

            while data.len() >= 64 {
                self.transform(Some(&data[..64]));
                data = &data[64..];
                self.count[1] = self.count[1].wrapping_add(1);
            }

            data.iter().for_each(|&byte| {
                self.buf[self.buf_len] = byte;
                self.buf_len += 1;
            });
        }
    }

    /// Returns the MD5 hash as a 16-byte array
    pub fn report(&mut self) -> [u8; 16] {
        let mut digest = [0u8; 16];
        self.update(None);

        let bit_count: u64 = ((self.count[1] as u64) << 29)
            + ((self.count[0] as u64) << 3)
            + ((self.buf_len as u64) << 3);

        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56 {
            while self.buf_len < 64 {
                self.buf[self.buf_len] = 0;
                self.buf_len += 1;
            }
            self.transform(None);
            self.buf_len = 0;
        }

        self.buf[self.buf_len..56].fill(0);
        self.buf[56..64]
            .iter_mut()
            .enumerate()
            .for_each(|(i, b)| *b = (bit_count >> (i << 3)) as u8);

        self.transform(None);

        let digest32: &mut [u32] = cast_slice_mut(&mut digest[..]);
        self.state
            .iter()
            .enumerate()
            .for_each(|(i, &chunk)| digest32[i] = chunk.to_be());

        self.state.fill(0);
        self.count.fill(0);
        self.buf.fill(0);

        digest
    }

    fn transform(&mut self, block: Option<&[u8]>) {
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];

        let block: &[u32] = if let Some(block) = block {
            cast_slice(block)
        } else {
            cast_slice(&self.buf[..])
        };

        a = ff(a, b, c, d, block[0], 7, 0xD76AA478);
        d = ff(d, a, b, c, block[1], 12, 0xE8C7B756);
        c = ff(c, d, a, b, block[2], 17, 0x242070DB);
        b = ff(b, c, d, a, block[3], 22, 0xC1BDCEEE);
        a = ff(a, b, c, d, block[4], 7, 0xF57C0FAF);
        d = ff(d, a, b, c, block[5], 12, 0x4787C62A);
        c = ff(c, d, a, b, block[6], 17, 0xA8304613);
        b = ff(b, c, d, a, block[7], 22, 0xFD469501);
        a = ff(a, b, c, d, block[8], 7, 0x698098D8);
        d = ff(d, a, b, c, block[9], 12, 0x8B44F7AF);
        c = ff(c, d, a, b, block[10], 17, 0xFFFF5BB1);
        b = ff(b, c, d, a, block[11], 22, 0x895CD7BE);
        a = ff(a, b, c, d, block[12], 7, 0x6B901122);
        d = ff(d, a, b, c, block[13], 12, 0xFD987193);
        c = ff(c, d, a, b, block[14], 17, 0xA679438E);
        b = ff(b, c, d, a, block[15], 22, 0x49B40821);

        a = gg(a, b, c, d, block[1], 5, 0xF61E2562);
        d = gg(d, a, b, c, block[6], 9, 0xC040B340);
        c = gg(c, d, a, b, block[11], 14, 0x265E5A51);
        b = gg(b, c, d, a, block[0], 20, 0xE9B6C7AA);
        a = gg(a, b, c, d, block[5], 5, 0xD62F105D);
        d = gg(d, a, b, c, block[10], 9, 0x02441453);
        c = gg(c, d, a, b, block[15], 14, 0xD8A1E681);
        b = gg(b, c, d, a, block[4], 20, 0xE7D3FBC8);
        a = gg(a, b, c, d, block[9], 5, 0x21E1CDE6);
        d = gg(d, a, b, c, block[14], 9, 0xC33707D6);
        c = gg(c, d, a, b, block[3], 14, 0xF4D50D87);
        b = gg(b, c, d, a, block[8], 20, 0x455A14ED);
        a = gg(a, b, c, d, block[13], 5, 0xA9E3E905);
        d = gg(d, a, b, c, block[2], 9, 0xFCEFA3F8);
        c = gg(c, d, a, b, block[7], 14, 0x676F02D9);
        b = gg(b, c, d, a, block[12], 20, 0x8D2A4C8A);

        a = hh(a, b, c, d, block[5], 4, 0xFFFA3942);
        d = hh(d, a, b, c, block[8], 11, 0x8771F681);
        c = hh(c, d, a, b, block[11], 16, 0x6D9D6122);
        b = hh(b, c, d, a, block[14], 23, 0xFDE5380C);
        a = hh(a, b, c, d, block[1], 4, 0xA4BEEA44);
        d = hh(d, a, b, c, block[4], 11, 0x4BDECFA9);
        c = hh(c, d, a, b, block[7], 16, 0xF6BB4B60);
        b = hh(b, c, d, a, block[10], 23, 0xBEBFBC70);
        a = hh(a, b, c, d, block[13], 4, 0x289B7EC6);
        d = hh(d, a, b, c, block[0], 11, 0xEAA127FA);
        c = hh(c, d, a, b, block[3], 16, 0xD4EF3085);
        b = hh(b, c, d, a, block[6], 23, 0x04881D05);
        a = hh(a, b, c, d, block[9], 4, 0xD9D4D039);
        d = hh(d, a, b, c, block[12], 11, 0xE6DB99E5);
        c = hh(c, d, a, b, block[15], 16, 0x1FA27CF8);
        b = hh(b, c, d, a, block[2], 23, 0xC4AC5665);

        a = ii(a, b, c, d, block[0], 6, 0xF4292244);
        d = ii(d, a, b, c, block[7], 10, 0x432AFF97);
        c = ii(c, d, a, b, block[14], 15, 0xAB9423A7);
        b = ii(b, c, d, a, block[5], 21, 0xFC93A039);
        a = ii(a, b, c, d, block[12], 6, 0x655B59C3);
        d = ii(d, a, b, c, block[3], 10, 0x8F0CCC92);
        c = ii(c, d, a, b, block[10], 15, 0xFFEFF47D);
        b = ii(b, c, d, a, block[1], 21, 0x85845DD1);
        a = ii(a, b, c, d, block[8], 6, 0x6FA87E4F);
        d = ii(d, a, b, c, block[15], 10, 0xFE2CE6E0);
        c = ii(c, d, a, b, block[6], 15, 0xA3014314);
        b = ii(b, c, d, a, block[13], 21, 0x4E0811A1);
        a = ii(a, b, c, d, block[4], 6, 0xF7537E82);
        d = ii(d, a, b, c, block[11], 10, 0xBD3AF235);
        c = ii(c, d, a, b, block[2], 15, 0x2AD7D2BB);
        b = ii(b, c, d, a, block[9], 21, 0xEB86D391);

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.count[0] = self.count[0].wrapping_add(64);

        if self.count[0] < 64 {
            self.count[1] = self.count[1].wrapping_add(1);
        }
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
