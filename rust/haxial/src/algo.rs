use bytemuck::{cast_slice, cast_slice_mut};

const CRCTAB: [u32; 256] = [
    0, 0x4C11DB7, 0x9823B6E, 0xD4326D9, 0x130476DC, 0x17C56B6B, 0x1A864DB2, 0x1E475005, 0x2608EDB8,
    0x22C9F00F, 0x2F8AD6D6, 0x2B4BCB61, 0x350C9B64, 0x31CD86D3, 0x3C8EA00A, 0x384FBDBD, 0x4C11DB70,
    0x48D0C6C7, 0x4593E01E, 0x4152FDA9, 0x5F15ADAC, 0x5BD4B01B, 0x569796C2, 0x52568B75, 0x6A1936C8,
    0x6ED82B7F, 0x639B0DA6, 0x675A1011, 0x791D4014, 0x7DDC5DA3, 0x709F7B7A, 0x745E66CD, 0x9823B6E0,
    0x9CE2AB57, 0x91A18D8E, 0x95609039, 0x8B27C03C, 0x8FE6DD8B, 0x82A5FB52, 0x8664E6E5, 0xBE2B5B58,
    0xBAEA46EF, 0xB7A96036, 0xB3687D81, 0xAD2F2D84, 0xA9EE3033, 0xA4AD16EA, 0xA06C0B5D, 0xD4326D90,
    0xD0F37027, 0xDDB056FE, 0xD9714B49, 0xC7361B4C, 0xC3F706FB, 0xCEB42022, 0xCA753D95, 0xF23A8028,
    0xF6FB9D9F, 0xFBB8BB46, 0xFF79A6F1, 0xE13EF6F4, 0xE5FFEB43, 0xE8BCCD9A, 0xEC7DD02D, 0x34867077,
    0x30476DC0, 0x3D044B19, 0x39C556AE, 0x278206AB, 0x23431B1C, 0x2E003DC5, 0x2AC12072, 0x128E9DCF,
    0x164F8078, 0x1B0CA6A1, 0x1FCDBB16, 0x18AEB13, 0x54BF6A4, 0x808D07D, 0xCC9CDCA, 0x7897AB07,
    0x7C56B6B0, 0x71159069, 0x75D48DDE, 0x6B93DDDB, 0x6F52C06C, 0x6211E6B5, 0x66D0FB02, 0x5E9F46BF,
    0x5A5E5B08, 0x571D7DD1, 0x53DC6066, 0x4D9B3063, 0x495A2DD4, 0x44190B0D, 0x40D816BA, 0xACA5C697,
    0xA864DB20, 0xA527FDF9, 0xA1E6E04E, 0xBFA1B04B, 0xBB60ADFC, 0xB6238B25, 0xB2E29692, 0x8AAD2B2F,
    0x8E6C3698, 0x832F1041, 0x87EE0DF6, 0x99A95DF3, 0x9D684044, 0x902B669D, 0x94EA7B2A, 0xE0B41DE7,
    0xE4750050, 0xE9362689, 0xEDF73B3E, 0xF3B06B3B, 0xF771768C, 0xFA325055, 0xFEF34DE2, 0xC6BCF05F,
    0xC27DEDE8, 0xCF3ECB31, 0xCBFFD686, 0xD5B88683, 0xD1799B34, 0xDC3ABDED, 0xD8FBA05A, 0x690CE0EE,
    0x6DCDFD59, 0x608EDB80, 0x644FC637, 0x7A089632, 0x7EC98B85, 0x738AAD5C, 0x774BB0EB, 0x4F040D56,
    0x4BC510E1, 0x46863638, 0x42472B8F, 0x5C007B8A, 0x58C1663D, 0x558240E4, 0x51435D53, 0x251D3B9E,
    0x21DC2629, 0x2C9F00F0, 0x285E1D47, 0x36194D42, 0x32D850F5, 0x3F9B762C, 0x3B5A6B9B, 0x315D626,
    0x7D4CB91, 0xA97ED48, 0xE56F0FF, 0x1011A0FA, 0x14D0BD4D, 0x19939B94, 0x1D528623, 0xF12F560E,
    0xF5EE4BB9, 0xF8AD6D60, 0xFC6C70D7, 0xE22B20D2, 0xE6EA3D65, 0xEBA91BBC, 0xEF68060B, 0xD727BBB6,
    0xD3E6A601, 0xDEA580D8, 0xDA649D6F, 0xC423CD6A, 0xC0E2D0DD, 0xCDA1F604, 0xC960EBB3, 0xBD3E8D7E,
    0xB9FF90C9, 0xB4BCB610, 0xB07DABA7, 0xAE3AFBA2, 0xAAFBE615, 0xA7B8C0CC, 0xA379DD7B, 0x9B3660C6,
    0x9FF77D71, 0x92B45BA8, 0x9675461F, 0x8832161A, 0x8CF30BAD, 0x81B02D74, 0x857130C3, 0x5D8A9099,
    0x594B8D2E, 0x5408ABF7, 0x50C9B640, 0x4E8EE645, 0x4A4FFBF2, 0x470CDD2B, 0x43CDC09C, 0x7B827D21,
    0x7F436096, 0x7200464F, 0x76C15BF8, 0x68860BFD, 0x6C47164A, 0x61043093, 0x65C52D24, 0x119B4BE9,
    0x155A565E, 0x18197087, 0x1CD86D30, 0x29F3D35, 0x65E2082, 0xB1D065B, 0xFDC1BEC, 0x3793A651,
    0x3352BBE6, 0x3E119D3F, 0x3AD08088, 0x2497D08D, 0x2056CD3A, 0x2D15EBE3, 0x29D4F654, 0xC5A92679,
    0xC1683BCE, 0xCC2B1D17, 0xC8EA00A0, 0xD6AD50A5, 0xD26C4D12, 0xDF2F6BCB, 0xDBEE767C, 0xE3A1CBC1,
    0xE760D676, 0xEA23F0AF, 0xEEE2ED18, 0xF0A5BD1D, 0xF464A0AA, 0xF9278673, 0xFDE69BC4, 0x89B8FD09,
    0x8D79E0BE, 0x803AC667, 0x84FBDBD0, 0x9ABC8BD5, 0x9E7D9662, 0x933EB0BB, 0x97FFAD0C, 0xAFB010B1,
    0xAB710D06, 0xA6322BDF, 0xA2F33668, 0xBCB4666D, 0xB8757BDA, 0xB5365D03, 0xB1F740B4,
];

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

/// Error types for cryptographic operations
#[derive(Debug)]
pub enum CryptError {
    Align(u8, usize),
    /// expected, got
    Length(usize, usize), // expected, got
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

/// Computes the augmented MD5 hash of the given data.
/// If the input is empty, it returns a predefined hash value.
/// Otherwise, it computes the MD5 hash and returns it as an array of 8 u32 values.
pub fn augmented_md5(input: &[u8]) -> [u32; 8] {
    if input.is_empty() {
        return [
            0xEEA339DA, 0x6EBEAECA, 0xD4B6B5E, 0xBA298EBA, 0xEFBF5532, 0xC4B5A218, 0x90186095,
            0x907D8AF,
        ];
    }

    let mut md5 = Md5::new();
    md5.update(Some(&input[..]));

    let hash = md5.report();
    let mut digest = [0u32; 8];

    digest[0..4].copy_from_slice(cast_slice(&hash[..]));
    digest[5] = digest[0];
    digest[6] = digest[1];
    digest[7] = fnv1a(&input[..], 1).to_be();

    digest
}

/// Computes the CRC32 checksum of the given data
pub fn crc32(input: &[u8], seed: u32) -> u32 {
    let mut crc = seed;

    input.iter().for_each(|b| {
        crc = crc.wrapping_shl(8) ^ CRCTAB[(crc.wrapping_shr(24) ^ (*b as u32)) as usize]
    });

    crc
}

/// Encrypts or decrypts data using a simple algorithm
/// The data must be aligned to 4 bytes.
/// The function returns a Result containing the encrypted or decrypted data.
/// If the data length is not a multiple of 4, an error is returned.
pub fn data_crypt(input: &[u8], seed: u32, mul: u32, add: u32) -> Result<Vec<u8>, CryptError> {
    if input.len() & 3 != 0 {
        return Err(CryptError::Align(4, input.len() & 3));
    }

    let mut output = vec![0u8; input.len()];
    let out_blocks: &mut [u32] = cast_slice_mut(&mut output[..]);
    let in_blocks: &[u32] = cast_slice(input);
    let mut seed = seed;

    in_blocks
        .iter()
        .zip(out_blocks.iter_mut())
        .for_each(|(&input, out)| {
            *out = input ^ seed.to_be();
            seed = seed.wrapping_mul(mul).wrapping_add(add);
        });

    Ok(output)
}

/// Encrypts or decrypts a file transfer block
/// The block must be 16 bytes long.
/// The function returns a Result containing the encrypted or decrypted block.
/// If the block length is not 16, an error is returned.
pub fn file_xfer_crypt(block: &[u8], decrypt: bool) -> Result<Vec<u8>, CryptError> {
    if block.len() != 16 {
        return Err(CryptError::Length(16, block.len()));
    }

    let mut buf = vec![0u8; 16];
    let mut words = [
        u32::from_ne_bytes(block[0..4].try_into().unwrap()),
        u32::from_ne_bytes(block[4..8].try_into().unwrap()),
        u32::from_ne_bytes(block[8..12].try_into().unwrap()),
        u32::from_ne_bytes(block[12..16].try_into().unwrap()),
    ];

    words.iter_mut().for_each(|w| *w = w.to_be());

    if !decrypt {
        words[2] ^= 0xA95A759B;
        words[0] ^= 0x6E7DFD34;
        words[1] ^= 0xE152DA04;
        words[3] ^= 0x6992E25;

        words[2] = words[2].rotate_right(7);
        words[0] = words[0].rotate_left(19);
        words[1] = words[1].rotate_left(6);
        words[3] = words[3].rotate_left(3);
    } else {
        words[0] = words[0].rotate_left(13) ^ 0x6E7DFD34;
        words[1] = words[1].rotate_right(6) ^ 0xE152DA04;
        words[2] = words[2].rotate_left(7) ^ 0xA95A759B;
        words[3] = words[3].rotate_right(3) ^ 0x6992E25;
    }

    words.iter_mut().for_each(|w| *w = u32::from_be(*w));

    buf[0..4].copy_from_slice(&words[0].to_ne_bytes());
    buf[4..8].copy_from_slice(&words[1].to_ne_bytes());
    buf[8..12].copy_from_slice(&words[2].to_ne_bytes());
    buf[12..16].copy_from_slice(&words[3].to_ne_bytes());

    Ok(buf)
}

/// Computes the FNV-1a hash of the given data
pub fn fnv1a(input: &[u8], seed: u32) -> u32 {
    let mut sum = seed;

    input
        .iter()
        .for_each(|b| sum = sum.wrapping_mul(0x1000193) ^ (*b as u32));

    sum
}

/// Encrypts or decrypts TCP packets
/// The key is a 32-bit integer, and the data must be aligned to 4 bytes.
/// The function returns a Result containing the encrypted or decrypted data.
/// If the data length is not a multiple of 4, an error is returned.
pub fn tcp_packet_crypt(key: u32, data: &[u8]) -> Result<Vec<u8>, CryptError> {
    if data.len() & 3 != 0 {
        return Err(CryptError::Align(4, data.len() & 3));
    }

    let mut output = vec![0u8; data.len()];
    let out_blocks: &mut [u32] = cast_slice_mut(&mut output[..]);
    let mut key = key;
    let in_blocks: &[u32] = cast_slice(data);

    in_blocks
        .iter()
        .zip(out_blocks.iter_mut())
        .for_each(|(&input, out)| {
            key = key.wrapping_shl(1).wrapping_add(0x4878); // 'Hx'
            *out = input ^ key.to_be();
        });

    Ok(output)
}

/// TODO: similar to file_xfer_crypt? Give this a proper name
pub fn transform_block(block: &[u8], encrypt: bool) -> Result<Vec<u8>, CryptError> {
    if block.len() != 16 {
        return Err(CryptError::Length(16, block.len()));
    }

    let mut buf = vec![0u8; 16];
    let buf32: &mut [u32] = cast_slice_mut(&mut buf[..]);
    let mut words = [
        u32::from_ne_bytes(block[0..4].try_into().unwrap()),
        u32::from_ne_bytes(block[4..8].try_into().unwrap()),
        u32::from_ne_bytes(block[8..12].try_into().unwrap()),
        u32::from_ne_bytes(block[12..16].try_into().unwrap()),
    ];

    words.iter_mut().for_each(|w| *w = w.to_be());

    if encrypt {
        words[1] = words[1].rotate_right(17) ^ 0x5F547A17;
        words[2] = words[2].rotate_right(4) ^ 0x69C83E35;
        words[0] = words[0].rotate_left(7) ^ 0x1B20E200;
        words[3] = words[3].rotate_right(5) ^ 0x8022E8D1;
    } else {
        words[0] = (words[2] ^ 0x1B20E200).rotate_left(7);
        words[1] = (words[1] ^ 0x5F547A17).rotate_left(15);
        words[2] = (words[2] ^ 0x69C83E35).rotate_right(4);
        words[3] = (words[3] ^ 0x8022E8D1).rotate_left(5);
    }

    words
        .iter()
        .enumerate()
        .for_each(|(i, &w)| buf32[i] = u32::from_be(w));

    Ok(buf)
}

/// Encrypts or decrypts UDP packets
/// The function uses a specific key and algorithm to transform the data.
/// The data must be aligned to 4 bytes.
/// The function returns a Result containing the encrypted or decrypted data.
/// If the data length is not a multiple of 4, an error is returned.
#[inline]
pub fn udp_packet_crypt(input: &[u8]) -> Result<Vec<u8>, CryptError> {
    data_crypt(input, 0xA5A16C4A, 0x41D28485, 12843)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_augmented_md5() {
        let input = b"Hello world!".to_vec();
        let digest = augmented_md5(&input);

        assert_eq!(
            digest,
            [
                232483535, 1520581664, 2384306924, 2906253792, 0, 232483535, 1520581664, 1216322572
            ]
        );
    }

    #[test]
    fn test_crc32() {
        let data = b"Hello, world!";
        let crc = crc32(&data[..], 0xDEADBEEF);

        assert_eq!(0x2C5E3398, crc);
    }

    #[test]
    fn test_data_crypt() {
        // Accounts.dat
        let data = [
            0xBF, 0x99, 0x6C, 0x39, 0x8E, 0x85, 0xA1, 0xD2, 0xCF, 0xB9, 0x00, 0x47, 0xAA, 0x9E,
            0xF0, 0x74, 0x80, 0xA7, 0xE9, 0xCD, 0x7D, 0x1A, 0x7D, 0x9A, 0x6A, 0x9D, 0x5A, 0x3B,
            0x7E, 0xF4, 0x9E, 0xD4, 0x1E, 0x1E, 0x87, 0x89, 0xFA, 0x1E, 0x6B, 0x9A, 0x1F, 0xC1,
            0xB1, 0x3F, 0x9F, 0x33, 0xDA, 0x0C, 0x46, 0xCB, 0xAF, 0x55, 0x64, 0xE3, 0xBD, 0x6A,
            0xC2, 0xAA, 0x22, 0x5B, 0x66, 0x4A, 0x8A, 0xF8, 0xB7, 0xE4, 0xEB, 0xD1, 0x80, 0xF8,
            0x46, 0x36, 0x92, 0xDE, 0x88, 0x36, 0x6C, 0x19, 0x5E, 0xA4,
        ];
        let dec = data_crypt(&data, 0x9AD22861, 0x41C64E6D, 12345).unwrap();

        assert_eq!(
            u32::from_be_bytes(dec[0..4].try_into().unwrap()),
            0x254B4458
        );
    }

    #[test]
    fn test_file_xfer_crypt_roundtrip() {
        let data = [0u8; 16];
        let enc = file_xfer_crypt(&data, false).unwrap();
        let dec = file_xfer_crypt(&enc, true).unwrap();
        assert_eq!(&data[..], &dec[..]);
    }

    #[test]
    fn test_fnv1a() {
        let data = b"Hello, world!";
        let sum = fnv1a(&data[..], 0xDEADBEEF);

        assert_eq!(0xE1CB7804, sum);
    }

    #[test]
    fn test_md5() {
        let data = b"Hello, world!";
        let mut md5 = Md5::new();
        md5.update(Some(&data[..]));
        let digest = md5.report();
        assert_eq!(
            digest,
            [
                216, 68, 244, 216, 165, 104, 77, 165, 93, 143, 149, 61, 9, 50, 31, 59
            ]
        );
    }

    #[test]
    fn test_tcp_packet_crypt_roundtrip() {
        let data = &b"Does it work?   ";
        let key = 0xDEADBEEF;

        let enc = tcp_packet_crypt(key, &data[..]).unwrap();
        let dec = tcp_packet_crypt(key, &enc[..]).unwrap();

        assert_eq!(&dec[..], &data[..]);
    }
}
