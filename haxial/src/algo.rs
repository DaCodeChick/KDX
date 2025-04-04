use bytemuck::cast_slice_mut;
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
pub fn lcx4878(key: &mut u32, data: &mut [u8]) {
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
		println!("{:?}", &data[..]);
		a95a(&mut data[..], true);
		assert_eq!(&data[..], &orig[..]);
	}

	#[test]
	fn test_lcx4878_roundtrip() {
		let mut data = b"Does it work?   ".to_vec();
		let origin = data.clone();
		let key = 0xDEADBEEF;
		let mut keymut = key;

		lcx4878(&mut keymut, &mut data[..]);
		println!("{:08X}\t{:?}", keymut, &data[..]);
		keymut = key;
		lcx4878(&mut keymut, &mut data[..]);
		println!("{:08X}", keymut);

		assert_eq!(origin, data);
	}
}
