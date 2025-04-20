use bytemuck::{cast_slice, cast_slice_mut};
use md5::{Digest, Md5};

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

#[derive(Debug)]
pub enum CryptError {
    Align(u8, usize),     // expected, got
    Length(usize, usize), // expected, got
}

/// A hybrid cryptographic hash function combining MD5 with Murmur 3 checksum augmentation.
///
/// # Behavior Details
///   1. Computes standard MD5 hash (first 128 bits of output)
///   2. Copies MD5 words [0] and [1] to output positions [5] and [6]
///   3. Computes a FNV-1a checksum of input (with byte swapping) for position [7]
///
/// # Security Notes
/// ❗ Not suitable for cryptographic purposes:
/// - The checksum weakens collision resistance
/// - Constant fallback breaks pseudorandomness
/// - MD5 is considered cryptographically broken
///
/// # Design Quirks
/// - The checksum at position [7] uses a FNV-1a sum of all input bytes
/// - Positions [5..6] duplicate MD5 words [0..1] (purpose unclear)
pub fn augmented_md5(input: &[u8]) -> [u32; 8] {
    if input.is_empty() {
        return [
            0xEEA339DA, 0x6EBEAECA, 0xD4B6B5E, 0xBA298EBA, 0xEFBF5532, 0xC4B5A218, 0x90186095,
            0x907D8AF,
        ];
    }

    let mut hasher = Md5::new();
    hasher.update(&input[..]);

    let hash = hasher.finalize();
    let mut digest = [0u32; 8];

    digest[0..4].copy_from_slice(cast_slice(&hash[..]));
    digest[5] = digest[0];
    digest[6] = digest[1];
    digest[7] = fnv1a(&input[..], 1).to_be();

    digest
}

/// Computes the cyclic redundancy code of the given data.
pub fn crc32(input: &[u8], seed: u32) -> u32 {
    let mut crc = seed;

    input.iter().for_each(|b| {
        crc = crc.wrapping_shl(8) ^ CRCTAB[(crc.wrapping_shr(24) ^ (*b as u32)) as usize]
    });

    crc
}

/// This is a multi-purpose LCG XOR encryption algorithm used in the KDX protocol.
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

/// This is used for KDX file transfers.
///
/// # Arguments
/// * `block` - Mutable 16-byte slice (must be exactly 16 bytes)
/// * `decrypt` - Boolean flag (false = encrypt, true = decrypt)
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

/// Computes the FNV-1a checksum of the given data
pub fn fnv1a(input: &[u8], seed: u32) -> u32 {
    let mut sum = seed;

    input
        .iter()
        .for_each(|b| sum = sum.wrapping_mul(0x1000193) ^ (*b as u32));

    sum
}

/// Encrypts or decrypts a network packet for TCP
///
/// # Arguments
/// * `key` - Initial key value
/// * `data` - Data to encrypt/decrypt
///
/// # Safety
/// Requires that `data.len()` is a multiple of 4 (32-bit aligned)
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

/// Used for encryption of UDP packets (server<->tracker)
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
                2636577670, 2234256665, 2353455350, 539665644, 0, 2636577670, 2234256665,
                1216322572
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
    fn test_tcp_packet_crypt_roundtrip() {
        let data = &b"Does it work?   ";
        let key = 0xDEADBEEF;

        let enc = tcp_packet_crypt(key, &data[..]).unwrap();
        let dec = tcp_packet_crypt(key, &enc[..]).unwrap();

        assert_eq!(&dec[..], &data[..]);
    }
}
