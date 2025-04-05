use bytemuck::{cast_slice, cast_slice_mut};
use md5::{Md5, Digest};
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
        words[3] ^= 0x06992E25;

        words[2] = words[2].rotate_right(7);
        words[0] = words[0].rotate_left(19);
        words[1] = words[1].rotate_left(6);
        words[3] = words[3].rotate_left(3);
    } else {
        words[0] = words[0].rotate_left(13) ^ 0x6E7DFD34;
        words[1] = words[1].rotate_right(6) ^ 0xE152DA04;
        words[2] = words[2].rotate_left(7) ^ 0xA95A759B;
        words[3] = words[3].rotate_right(3) ^ 0x06992E25;
    }

    words.iter_mut().for_each(|w| *w = u32::from_be(*w));
    
    block[0..4].copy_from_slice(&words[0].to_le_bytes());
    block[4..8].copy_from_slice(&words[1].to_le_bytes());
    block[8..12].copy_from_slice(&words[2].to_le_bytes());
    block[12..16].copy_from_slice(&words[3].to_le_bytes());
}


/// A hybrid cryptographic hash function combining MD5 with custom checksum augmentation.
///
/// This algorithm has two distinct modes:
/// 1. **Empty Input**: Returns a hardcoded 256-bit digest of constant values
/// 2. **Non-empty Input**: Computes an MD5 hash combined with a custom byte-sum checksum
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
		return [0xEEA339DA, 0x6EBEAECA, 0xD4B6B5E, 0xBA298EBA,
			0xEFBF5532, 0xC4B5A218, 0x90186095, 0x907D8AF];
	}

	let mut hasher = Md5::new();
	hasher.update(&input[..]);

	let hash = hasher.finalize();
	let mut digest = [0u32; 8];

	digest[0..4].copy_from_slice(cast_slice(&hash[..]));
	digest[5] = digest[0];
	digest[6] = digest[1];

	let mut cur = Cursor::new(&input[..]);
	digest[7] = murmur3_32(&mut cur, 1)
				.unwrap()
				.to_be();
	
	digest
}


/// Simple XOR cipher with key evolution
///
/// # Arguments
/// * `key` - Initial key value (will be modified during operation)
/// * `data` - Mutable byte slice to encrypt/decrypt
///
/// # Returns
/// The final key state after processing
///
/// # Safety
/// Requires that `data.len()` is a multiple of 4 (32-bit aligned)
pub fn lcxhx(key: &mut u32, data: &mut [u8]) {
	assert_eq!(
        data.len() % size_of::<u32>(),
        0,
        "Data length must be multiple of 4 bytes"
    );

	let data32: &mut [u32] = cast_slice_mut(data);

	for word in data32.iter_mut() {
		*key = key.wrapping_shl(1).wrapping_add(0x4878);
		*word ^= key.to_be();
	}
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
		
		digest.iter()
			.for_each(|x| print!("{:04X}, ", x));
		println!();
	}


	#[test]
	fn test_lcxhx_roundtrip() {
		let mut data = b"Does it work?   ".to_vec();
		let origin = data.clone();
		let key = 0xDEADBEEF;
		let mut keymut = key;

		lcxhx(&mut keymut, &mut data[..]);
		keymut = key;
		lcxhx(&mut keymut, &mut data[..]);

		assert_eq!(origin, data);
	}
}
