use bytemuck::{cast_slice, cast_slice_mut};
use md5::{Digest, Md5};
use murmur3::murmur3_32;
use std::io::Cursor;
use std::mem::size_of;

/// Custom cryptographic transform operating on a 128-bit (16-byte) block
///
/// # Arguments
/// * `block` - Mutable 16-byte slice (must be exactly 16 bytes)
/// * `decrypt` - Boolean flag (false = encrypt, true = decrypt)
///
/// # Panics
/// Will panic if block length != 16 bytes
pub fn a95a(block: &mut [u8], decrypt: bool) {
    assert_eq!(block.len(), 16, "Block must be exactly 16 bytes");

    let mut words = [
        u32::from_le_bytes(block[0..4].try_into().unwrap()),
        u32::from_le_bytes(block[4..8].try_into().unwrap()),
        u32::from_le_bytes(block[8..12].try_into().unwrap()),
        u32::from_le_bytes(block[12..16].try_into().unwrap()),
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

    block[0..4].copy_from_slice(&words[0].to_le_bytes());
    block[4..8].copy_from_slice(&words[1].to_le_bytes());
    block[8..12].copy_from_slice(&words[2].to_le_bytes());
    block[12..16].copy_from_slice(&words[3].to_le_bytes());
}

/// A hybrid cryptographic hash function combining MD5 with custom checksum augmentation.
///
/// # Behavior Details
///   1. Computes standard MD5 hash (first 128 bits of output)
///   2. Copies MD5 words [0] and [1] to output positions [5] and [6]
///   3. Computes a byte-sum checksum of input (with byte swapping) for position [7]
///
/// # Security Notes
/// ❗ Not suitable for cryptographic purposes:
/// - The checksum weakens collision resistance
/// - Constant fallback breaks pseudorandomness
/// - MD5 is considered cryptographically broken
///
/// # Design Quirks
/// - The checksum at position [7] uses a byte-swapped sum of all input bytes
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

    let mut cur = Cursor::new(&input[..]);
    digest[7] = murmur3_32(&mut cur, 1).unwrap().to_be();

    digest
}

/// LCG XOR cipher
/// Warning: Not cryptographically secure.
pub fn lcg_xor(input: &mut [u8]) {
    let mut state = 0x9AD22861u32;
    let data32: &mut [u32] = cast_slice_mut(input);

    data32.iter_mut().for_each(|w| {
        *w ^= state.to_be();
        state = state.wrapping_mul(0x41C64E6D).wrapping_add(12345);
    });
}

/// Simple XOR cipher with key evolution
///
/// # Arguments
/// * `key` - Initial key value
/// * `data` - Mutable byte slice to encrypt/decrypt
///
/// # Safety
/// Requires that `data.len()` is a multiple of 4 (32-bit aligned)
pub fn lcx_hx(key: u32, data: &mut [u8]) {
    assert_eq!(
        data.len() % size_of::<u32>(),
        0,
        "Data length must be multiple of 4 bytes"
    );

    let mut key = key;
    let data32: &mut [u32] = cast_slice_mut(data);

    data32.iter_mut().for_each(|w| {
        key = key.wrapping_shl(1).wrapping_add(0x4878); // 'Hx'
        *w ^= key.to_be();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a95a_roundtrip() {
        let mut data = [0u8; 16];
        let orig = [0u8; 16];
        a95a(&mut data[..], false);
        a95a(&mut data[..], true);
        assert_eq!(&data[..], &orig[..]);
    }

    #[test]
    fn test_augmented_md5() {
        let input = b"Hello world!".to_vec();
        let digest = augmented_md5(&input[..]);

        assert_eq!(
            digest,
            [
                0x9D26FB86, 0x852C0D19, 0x8C46E0F6, 0x202AA4EC, 0, 0x9D26FB86, 0x852C0D19,
                0x11CCCF86
            ]
        );
    }

    #[test]
    fn test_lcg_xor() {
        let mut buf = [
            0xBF, 0x99, 0x6C, 0x39, 0x8E, 0x85, 0xA1, 0xD2, 0xCF, 0xB9, 0x00, 0x47, 0xAA, 0x9E,
            0xF0, 0x74, 0x80, 0xA7, 0xE9, 0xCD, 0x7D, 0x1A, 0x7D, 0x9A, 0x6A, 0x9D, 0x5A, 0x3B,
            0x7E, 0xF4, 0x9E, 0xD4, 0x1E, 0x1E, 0x87, 0x89, 0xFA, 0x1E, 0x6B, 0x9A, 0x1F, 0xC1,
            0xB1, 0x3F, 0x9F, 0x33, 0xDA, 0x0C, 0x46, 0xCB, 0xAF, 0x55, 0x64, 0xE3, 0xBD, 0x6A,
            0xC2, 0xAA, 0x22, 0x5B, 0x66, 0x4A, 0x8A, 0xF8, 0xB7, 0xE4, 0xEB, 0xD1, 0x80, 0xF8,
            0x46, 0x36, 0x92, 0xDE, 0x88, 0x36, 0x6C, 0x19, 0x5E, 0xA4,
        ];
        lcg_xor(&mut buf);
        assert_eq!(
            u32::from_be_bytes(buf[0..4].try_into().unwrap()),
            0x254B4458
        );
    }

    #[test]
    fn test_lcx_hx_roundtrip() {
        let mut data = b"Does it work?   ".to_vec();
        let origin = data.clone();
        let key = 0xDEADBEEF;

        lcx_hx(key, &mut data[..]);
        lcx_hx(key, &mut data[..]);

        assert_eq!(origin, data);
    }
}
