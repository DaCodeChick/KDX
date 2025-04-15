use bytemuck::{cast_slice, cast_slice_mut};
use md5::{Digest, Md5};
use murmur3::murmur3_32;
use std::io::Cursor;

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
///   3. Computes a Murmur 3 checksum of input (with byte swapping) for position [7]
///
/// # Security Notes
/// ❗ Not suitable for cryptographic purposes:
/// - The checksum weakens collision resistance
/// - Constant fallback breaks pseudorandomness
/// - MD5 is considered cryptographically broken
///
/// # Design Quirks
/// - The checksum at position [7] uses a Murmur 3 sum of all input bytes
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
    digest[7] = murmur3_32(&mut Cursor::new(&input[..]), 1).unwrap().to_be();

    digest
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
                0x9D26FB86, 0x852C0D19, 0x8C46E0F6, 0x202AA4EC, 0, 0x9D26FB86, 0x852C0D19,
                0x11CCCF86
            ]
        );
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
    fn test_tcp_packet_crypt_roundtrip() {
        let data = &b"Does it work?   ";
        let key = 0xDEADBEEF;

        let enc = tcp_packet_crypt(key, &data[..]).unwrap();
        let dec = tcp_packet_crypt(key, &enc[..]).unwrap();

        assert_eq!(&dec[..], &data[..]);
    }
}
