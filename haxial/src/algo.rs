use bytemuck::{cast_slice, cast_slice_mut};
use chrono::Local;
use md5::{Digest, Md5};
use murmur3::murmur3_32;
use std::cmp::min;
use std::io::Cursor;
use std::mem::size_of;

const LCG_ADD: u32 = 12345;
const LCG_MUL: u32 = 0x41C64E6D;

/// Cryptographic random data generator using a mixing algorithm with
/// MD5 for entropy.
pub struct RandomState {
    buf: [u32; 64],
    idx: usize,
    seed: u32,
}

impl RandomState {
    pub fn new() -> Self {
        Self {
            buf: [0u32; 64],
            idx: 0,
            seed: Local::now().timestamp() as u32,
        }
    }

    /// Generates random data into the output buffer
    ///
    /// # Arguments
    /// * `output` - Buffer to fill with random data
    pub fn generate_random(&mut self, output: &mut [u32]) {
        let mut remaining = output.len();
        if remaining == 0 {
            return;
        }

        let mut output_ptr = 0;

        while remaining > 0 {
            // MD5 hash the buffer
            let mut hasher = Md5::new();
            hasher.update(cast_slice(&self.buf));
            let hash_result = hasher.finalize();
            let xor_result = self.xor_chain(0xFFFFFFFF);
            let to_copy = min(remaining, 8);

            // Copy hash result to output
            for i in 0..to_copy {
                let val = u32::from_le_bytes([
                    hash_result[i << 2],
                    hash_result[(i << 2) + 1],
                    hash_result[(i << 2) + 2],
                    hash_result[(i << 2) + 3],
                ]);
                output[output_ptr + i] = val;
            }

            output_ptr += to_copy;
            remaining -= to_copy;

            // Rotate buffer based on XOR result
            if xor_result & 1 == 0 {
                // Rotate right by 2 bytes
                let temp = self.buf[63] >> 16;
                for i in (1..64).rev() {
                    self.buf[i] = (self.buf[i] << 16) | (self.buf[i - 1] >> 16);
                }
                self.buf[0] = (self.buf[0] << 16) | temp;
            } else {
                // Rotate left by 1 byte
                let temp = self.buf[0] >> 24;
                for i in 0..63 {
                    self.buf[i] = (self.buf[i] << 8) | (self.buf[i + 1] >> 24);
                }
                self.buf[63] = (self.buf[63] << 8) | temp;
            }

            // Apply random bit rotations based on random seed
            let case = Local::now().timestamp() as u32;
            match case {
                0 => {
                    self.buf[1] = self.buf[1].rotate_left(28);
                    self.buf[3] = self.buf[3].rotate_left(29).wrapping_add(1);
                    self.buf[10] = self.buf[10].rotate_left(31);
                    self.buf[24] = self.buf[24].rotate_right(30);
                    self.buf[45] = self.buf[45].rotate_right(29);
                    self.buf[48] = self.buf[48].rotate_left(31);
                    self.buf[54] = self.buf[54].rotate_right(31);
                    self.buf[55] = self.buf[55].rotate_left(23);
                }
                1 => {
                    self.buf[6] = self.buf[6].rotate_left(31);
                    self.buf[14] = self.buf[14].rotate_right(29);
                    self.buf[20] = self.buf[20].rotate_right(31);
                    self.buf[23] = self.buf[23].rotate_right(27);
                    self.buf[35] = self.buf[35].rotate_left(14).wrapping_add(1);
                    self.buf[39] = self.buf[39].rotate_left(31);
                    self.buf[52] = self.buf[52].rotate_left(31);
                    self.buf[53] = self.buf[53].rotate_right(25);
                }
                2 => {
                    self.buf[0] = self.buf[0].rotate_left(31);
                    self.buf[7] = self.buf[7].rotate_right(26);
                    self.buf[18] = self.buf[18].rotate_left(31);
                    self.buf[32] = self.buf[32].rotate_right(30);
                    self.buf[35] = self.buf[35].rotate_left(31);
                    self.buf[40] = self.buf[40].rotate_right(31);
                    self.buf[57] = self.buf[57].rotate_left(31);
                    self.buf[63] = self.buf[63].rotate_right(29).wrapping_add(1);
                }
                _ => {
                    self.buf[2] = self.buf[2].rotate_right(31);
                    self.buf[9] = self.buf[9].rotate_right(31);
                    self.buf[21] = self.buf[21].rotate_right(31);
                    self.buf[30] = self.buf[30].rotate_left(31).wrapping_add(1);
                    self.buf[45] = self.buf[45].rotate_right(31);
                    self.buf[49] = self.buf[49].rotate_right(31);
                    self.buf[53] = self.buf[53].rotate_left(31);
                    self.buf[56] = self.buf[56].rotate_right(31);
                }
            }
        }
    }

    /// Pseudo random number generation
    pub fn random(&mut self) -> u32 {
        let mut sum = murmur3_32(
            &mut Cursor::new(cast_slice::<u32, u8>(&self.buf)),
            self.seed,
        )
        .unwrap();

        self.seed = self.seed.wrapping_mul(LCG_MUL).wrapping_add(LCG_ADD);
        sum ^= self.seed;
        self.buf[self.idx] ^= sum;
        self.idx = (sum & 63) as usize;

        sum
    }

    fn xor_chain(&self, initial: u32) -> u32 {
        let mut val = !initial;
        for chunk in self.buf.chunks_exact(8) {
            val ^= chunk[0]
                ^ chunk[1]
                ^ chunk[2]
                ^ chunk[3]
                ^ chunk[4]
                ^ chunk[5]
                ^ chunk[6]
                ^ chunk[7];
        }
        val
    }
}

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

/// LCG XOR cipher
/// Warning: Not cryptographically secure.
pub fn lcg_xor(input: &mut [u8]) {
    let mut state = 0x9AD22861u32;
    let data32: &mut [u32] = cast_slice_mut(input);

    data32.iter_mut().for_each(|w| {
        *w ^= state.to_be();
        state = state.wrapping_mul(LCG_MUL).wrapping_add(LCG_ADD);
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
