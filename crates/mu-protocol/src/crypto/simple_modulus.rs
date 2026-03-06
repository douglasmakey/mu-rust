/// SimpleModulus cipher — the block cipher used to encrypt/decrypt C3/C4 MU Online packets.
///
/// New variant (used here): 8-byte plaintext blocks → 11-byte ciphertext blocks.
/// Each block holds four 18-bit modular values packed tightly into 9 bytes, plus a
/// 2-byte trailer carrying the block's byte count and checksum.
///
/// Algorithm ported from OpenMU (MIT licence).
use thiserror::Error;

use crate::crypto::header_size;

pub const DECRYPTED_BLOCK_SIZE: usize = 8;
pub const ENCRYPTED_BLOCK_SIZE: usize = 11;

const BLOCK_SIZE_XOR_KEY: u8 = 0x3D;
const BLOCK_CHECKSUM_XOR_KEY: u8 = 0xF8;

// Four 18-bit values are packed contiguously (MSB-first within each value)
// into a 9-byte region. Value[i] starts at bit i*18:
//
//   i=0: bits  0..17  → bytes 0-2  (byte offset = 0, bit offset = 0)
//   i=1: bits 18..35  → bytes 2-4  (byte offset = 2, bit offset = 2)
//   i=2: bits 36..53  → bytes 4-6  (byte offset = 4, bit offset = 4)
//   i=3: bits 54..71  → bytes 6-8  (byte offset = 6, bit offset = 6)
//
// Note: byte_offset(i) == bit_offset(i) == i*2 for all i in 0..4.

/// Byte offset of slot `i` in the 9-byte packed region.
const SLOT_OFFSET: [usize; 4] = [0, 2, 4, 6];
/// Mask for the bits of slot `i` in its first byte (high bits).
const FIRST_MASK: [u32; 4] = [0xFF, 0x3F, 0x0F, 0x03];
/// Mask for the high-2-bits of slot `i` stored in its third byte.
const REMAINDER_MASK: [u32; 4] = [0xC0, 0x30, 0x0C, 0x03];

/// Key material for one direction of SimpleModulus (encrypt or decrypt).
#[derive(Debug, Clone, Copy)]
pub struct SimpleModulusKeys {
    pub modulus_key: [u32; 4],
    pub xor_key: [u32; 4],
    /// The directional key — either the encrypt or decrypt key depending on
    /// which constant (`SERVER_ENCRYPT`, `SERVER_DECRYPT`, …) is used.
    pub operation_key: [u32; 4],
}

/// Server → client encryption keys.
pub const SERVER_ENCRYPT: SimpleModulusKeys = SimpleModulusKeys {
    modulus_key: [73326, 109989, 98843, 171058],
    operation_key: [13169, 19036, 35482, 29587],
    xor_key: [62004, 64409, 35374, 64599],
};

/// Client → server decryption keys (server side).
pub const SERVER_DECRYPT: SimpleModulusKeys = SimpleModulusKeys {
    modulus_key: [128079, 164742, 70235, 106898],
    operation_key: [31544, 2047, 57011, 10183],
    xor_key: [48413, 46165, 15171, 37433],
};

/// Client-side keys — only used in tests to simulate the remote peer.
#[cfg(test)]
pub(crate) const CLIENT_ENCRYPT: SimpleModulusKeys = SimpleModulusKeys {
    modulus_key: [128079, 164742, 70235, 106898],
    operation_key: [23489, 11911, 19816, 13647],
    xor_key: [48413, 46165, 15171, 37433],
};

#[cfg(test)]
pub(crate) const CLIENT_DECRYPT: SimpleModulusKeys = SimpleModulusKeys {
    modulus_key: [73326, 109989, 98843, 171058],
    operation_key: [18035, 30340, 24701, 11141],
    xor_key: [62004, 64409, 35374, 64599],
};

#[derive(Debug, Error)]
pub enum SimpleModulusError {
    #[error("encrypted content length must be a multiple of {ENCRYPTED_BLOCK_SIZE}")]
    InvalidContentSize,

    #[error("block size {actual} exceeds maximum {DECRYPTED_BLOCK_SIZE}")]
    InvalidBlockSize { actual: u8 },

    #[error("block checksum mismatch: expected {expected:#04x}, got {actual:#04x}")]
    InvalidChecksum { expected: u8, actual: u8 },

    #[error("counter mismatch: expected {expected}, got {actual}")]
    CounterMismatch { expected: u8, actual: u8 },
}

/// Pack one 18-bit value into the 9-byte output region at slot `i`.
fn write_value(buf: &mut [u8], i: usize, value: u32) {
    let off = SLOT_OFFSET[i];
    let bo = SLOT_OFFSET[i] as u32;

    // Byte-swap mirrors BinaryPrimitives.ReverseEndianness in the C# original.
    let swapped = value.swap_bytes();
    buf[off] |= ((swapped >> (24 + bo)) & FIRST_MASK[i]) as u8;
    buf[off + 1] = (swapped >> (16 + bo)) as u8;
    buf[off + 2] = ((swapped >> (8 + bo)) & (0xFF << (8 - bo))) as u8;
    buf[off + 2] |= (((value >> 16) << (6 - bo)) & REMAINDER_MASK[i]) as u8;
}

/// Unpack one 18-bit value from the 9-byte input region at slot `i`.
fn read_value(buf: &[u8], i: usize) -> u32 {
    let off = SLOT_OFFSET[i];
    let bo = SLOT_OFFSET[i] as u32;

    let mut result: u32 = 0;
    result += (buf[off] as u32 & FIRST_MASK[i]) << (24 + bo);
    result += (buf[off + 1] as u32) << (16 + bo);
    result += (buf[off + 2] as u32 & (0xFF << (8 - bo))) << (8 + bo);
    result = result.swap_bytes();
    result += ((buf[off + 2] as u32 & REMAINDER_MASK[i]) << 16) >> (6 - bo);
    result
}

/// Encrypt one 8-byte plaintext block into an 11-byte ciphertext block.
///
/// `block_size` is the number of meaningful bytes in `input` (1..=8); the rest
/// must already be zeroed.
fn encrypt_block(
    input: &[u8; DECRYPTED_BLOCK_SIZE],
    output: &mut [u8; ENCRYPTED_BLOCK_SIZE],
    block_size: usize,
    keys: &SimpleModulusKeys,
) {
    output.fill(0);

    // Interpret the 8-byte block as four little-endian u16 values.
    let inp = [
        u16::from_le_bytes([input[0], input[1]]) as u32,
        u16::from_le_bytes([input[2], input[3]]) as u32,
        u16::from_le_bytes([input[4], input[5]]) as u32,
        u16::from_le_bytes([input[6], input[7]]) as u32,
    ];

    // Forward modular pass.
    let mut r = [0u32; 4];
    r[0] = ((keys.xor_key[0] ^ inp[0]) * keys.operation_key[0]) % keys.modulus_key[0];
    for i in 1..4 {
        r[i] = ((keys.xor_key[i] ^ (inp[i] ^ (r[i - 1] & 0xFFFF))) * keys.operation_key[i])
            % keys.modulus_key[i];
    }

    // XOR-chain pass (all but the last).
    for i in 0..3 {
        r[i] ^= keys.xor_key[i] ^ (r[i + 1] & 0xFFFF);
    }

    // Pack into the first 9 bytes of the output.
    for i in 0..4 {
        write_value(output, i, r[i]);
    }

    // Trailer: encrypted block size (byte 9) and checksum (byte 10).
    let mut checksum = BLOCK_CHECKSUM_XOR_KEY;
    for b in &input[..block_size] {
        checksum ^= b;
    }
    output[9] = (block_size as u8 ^ BLOCK_SIZE_XOR_KEY) ^ checksum;
    output[10] = checksum;
}

/// Decrypt one 11-byte ciphertext block into an 8-byte plaintext block.
///
/// Returns the number of meaningful decrypted bytes (1..=8).
fn decrypt_block(
    input: &[u8; ENCRYPTED_BLOCK_SIZE],
    output: &mut [u8; DECRYPTED_BLOCK_SIZE],
    keys: &SimpleModulusKeys,
) -> Result<usize, SimpleModulusError> {
    // Unpack the four 18-bit values.
    let mut r: [u32; 4] = std::array::from_fn(|i| read_value(input, i));

    // Reverse the XOR chain.
    for i in (1..4).rev() {
        r[i - 1] ^= keys.xor_key[i - 1] ^ (r[i] & 0xFFFF);
    }

    // Reverse the modular pass and write as little-endian u16 pairs.
    // Use u64 to avoid overflow before the modulus operation.
    for i in 0..4 {
        let mut val = keys.xor_key[i]
            ^ ((r[i] as u64 * keys.operation_key[i] as u64) % keys.modulus_key[i] as u64) as u32;
        if i > 0 {
            val ^= r[i - 1] & 0xFFFF;
        }
        let bytes = (val as u16).to_le_bytes();
        output[i * 2] = bytes[0];
        output[i * 2 + 1] = bytes[1];
    }

    // Decode the trailer.
    let block_size = input[9] ^ input[10] ^ BLOCK_SIZE_XOR_KEY;
    if block_size as usize > DECRYPTED_BLOCK_SIZE {
        return Err(SimpleModulusError::InvalidBlockSize { actual: block_size });
    }

    // Verify checksum over all 8 output bytes (padding bytes are zero).
    let checksum = output
        .iter()
        .fold(BLOCK_CHECKSUM_XOR_KEY, |acc, &b| acc ^ b);
    if input[10] != checksum {
        return Err(SimpleModulusError::InvalidChecksum {
            expected: checksum,
            actual: input[10],
        });
    }

    Ok(block_size as usize)
}

fn set_packet_size(buf: &mut [u8], size: usize) {
    match buf[0] {
        0xC3 => buf[1] = size as u8,
        0xC4 => {
            buf[1] = (size >> 8) as u8;
            buf[2] = size as u8;
        }
        _ => {}
    }
}

/// Encrypt a C3/C4 packet.
///
/// The `counter` byte is prepended to the plaintext before the first block and
/// incremented on each call. Non-encrypted packet types (C1/C2) are returned
/// unchanged.
pub fn encrypt(packet: &[u8], keys: &SimpleModulusKeys, counter: &mut u8) -> Vec<u8> {
    if packet[0] < 0xC3 {
        return packet.to_vec();
    }

    let hdr = header_size(packet[0]);
    let content = &packet[hdr..];
    // Content length with the prepended counter byte.
    let content_with_counter = content.len() + 1;
    let num_blocks = content_with_counter.div_ceil(DECRYPTED_BLOCK_SIZE);
    let total = hdr + num_blocks * ENCRYPTED_BLOCK_SIZE;

    let mut out = vec![0u8; total];
    out[0] = packet[0];
    set_packet_size(&mut out, total);

    let mut input_buf = [0u8; DECRYPTED_BLOCK_SIZE];
    let mut src = 0usize; // offset into `content`
    let mut dst = hdr; // offset into `out`

    // First block: [counter, content[0..7]]
    {
        input_buf[0] = *counter;
        let copy = content.len().min(DECRYPTED_BLOCK_SIZE - 1);
        input_buf[1..1 + copy].copy_from_slice(&content[..copy]);
        input_buf[1 + copy..].fill(0);

        let mut enc = [0u8; ENCRYPTED_BLOCK_SIZE];
        encrypt_block(
            &input_buf,
            &mut enc,
            (content.len() + 1).min(DECRYPTED_BLOCK_SIZE),
            keys,
        );
        out[dst..dst + ENCRYPTED_BLOCK_SIZE].copy_from_slice(&enc);

        src += DECRYPTED_BLOCK_SIZE - 1;
        dst += ENCRYPTED_BLOCK_SIZE;
    }

    // Remaining blocks.
    while src < content.len() {
        let block_size = (content.len() - src).min(DECRYPTED_BLOCK_SIZE);
        input_buf[..block_size].copy_from_slice(&content[src..src + block_size]);
        input_buf[block_size..].fill(0);

        let mut enc = [0u8; ENCRYPTED_BLOCK_SIZE];
        encrypt_block(&input_buf, &mut enc, block_size, keys);
        out[dst..dst + ENCRYPTED_BLOCK_SIZE].copy_from_slice(&enc);

        src += DECRYPTED_BLOCK_SIZE;
        dst += ENCRYPTED_BLOCK_SIZE;
    }

    *counter = counter.wrapping_add(1);
    out
}

/// Decrypt a C3/C4 packet.
///
/// The counter embedded in the first plaintext block is validated against
/// `counter` and then stripped. `counter` is incremented on success.
/// Non-encrypted packet types are returned unchanged.
pub fn decrypt(
    packet: &[u8],
    keys: &SimpleModulusKeys,
    counter: &mut u8,
) -> Result<Vec<u8>, SimpleModulusError> {
    if packet[0] < 0xC3 {
        return Ok(packet.to_vec());
    }

    let hdr = header_size(packet[0]);
    let content = &packet[hdr..];

    if content.len() % ENCRYPTED_BLOCK_SIZE != 0 {
        return Err(SimpleModulusError::InvalidContentSize);
    }

    let mut dec_buf = vec![0u8; (content.len() / ENCRYPTED_BLOCK_SIZE) * DECRYPTED_BLOCK_SIZE];
    let mut total_dec = 0usize; // meaningful bytes including counter

    for (b, chunk) in content.chunks_exact(ENCRYPTED_BLOCK_SIZE).enumerate() {
        let out_slice: &mut [u8; DECRYPTED_BLOCK_SIZE] = (&mut dec_buf
            [b * DECRYPTED_BLOCK_SIZE..(b + 1) * DECRYPTED_BLOCK_SIZE])
            .try_into()
            .unwrap();
        total_dec += decrypt_block(chunk.try_into().unwrap(), out_slice, keys)?;
    }

    // First byte is the counter.
    if dec_buf[0] != *counter {
        return Err(SimpleModulusError::CounterMismatch {
            expected: *counter,
            actual: dec_buf[0],
        });
    }

    // Strip the counter byte; real content follows.
    let real_content_len = total_dec.saturating_sub(1);
    let real_content = &dec_buf[1..1 + real_content_len];

    let total = hdr + real_content_len;
    let mut out = vec![0u8; total];
    out[0] = packet[0];
    set_packet_size(&mut out, total);
    out[hdr..].copy_from_slice(real_content);

    *counter = counter.wrapping_add(1);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `read_value` is the exact inverse of `write_value` for all
    /// four slot indices and a variety of 18-bit values.
    #[test]
    fn pack_unpack_roundtrip() {
        let test_values: &[u32] = &[0, 1, 0xFFFF, 0x1FFFF, 0x2FFFF, 0x30000, 12345, 98765];
        for &v in test_values {
            for i in 0..4 {
                let mut buf = [0u8; ENCRYPTED_BLOCK_SIZE];
                write_value(&mut buf, i, v);
                let got = read_value(&buf, i);
                assert_eq!(got, v, "roundtrip failed for value={v} at index={i}");
            }
        }
    }

    /// Encrypt → decrypt a C3 packet and verify the plaintext is recovered.
    #[test]
    fn encrypt_decrypt_roundtrip_c3() {
        let enc_keys = SERVER_ENCRYPT;
        let dec_keys = CLIENT_DECRYPT;

        let plaintext: Vec<u8> = vec![0xC3, 0x07, 0xF3, 0x00, 0x01, 0x02, 0x03];

        let mut enc_counter = 0u8;
        let encrypted = encrypt(&plaintext, &enc_keys, &mut enc_counter);
        assert_eq!(enc_counter, 1);
        assert_eq!(encrypted[0], 0xC3);

        let mut dec_counter = 0u8;
        let decrypted = decrypt(&encrypted, &dec_keys, &mut dec_counter).unwrap();
        assert_eq!(dec_counter, 1);
        assert_eq!(decrypted, plaintext);
    }

    /// Counters must match between encryptor and decryptor.
    #[test]
    fn counter_mismatch_returns_error() {
        let enc_keys = SERVER_ENCRYPT;
        let dec_keys = CLIENT_DECRYPT;

        let plaintext: Vec<u8> = vec![0xC3, 0x04, 0xF3, 0x00];
        let mut enc_counter = 5u8;
        let encrypted = encrypt(&plaintext, &enc_keys, &mut enc_counter);

        let mut dec_counter = 0u8; // wrong
        let result = decrypt(&encrypted, &dec_keys, &mut dec_counter);
        assert!(matches!(
            result,
            Err(SimpleModulusError::CounterMismatch { .. })
        ));
    }

    /// Non-encrypted packet types must pass through unchanged.
    #[test]
    fn c1_packet_passthrough() {
        let keys = SERVER_ENCRYPT;
        let packet = vec![0xC1, 0x04, 0x00, 0x01];
        let mut counter = 0u8;
        assert_eq!(encrypt(&packet, &keys, &mut counter), packet);
        assert_eq!(
            counter, 0,
            "counter should not change for non-encrypted packets"
        );
    }

    /// Multiple sequential packets must each use an incremented counter.
    #[test]
    fn counter_increments_across_packets() {
        let enc_keys = SERVER_ENCRYPT;
        let dec_keys = CLIENT_DECRYPT;

        let mut enc_ctr = 0u8;
        let mut dec_ctr = 0u8;

        for _ in 0..5 {
            let plain = vec![0xC3, 0x05, 0xAA, 0xBB, 0xCC];
            let enc = encrypt(&plain, &enc_keys, &mut enc_ctr);
            let dec = decrypt(&enc, &dec_keys, &mut dec_ctr).unwrap();
            assert_eq!(dec, plain);
        }
        assert_eq!(enc_ctr, 5);
        assert_eq!(dec_ctr, 5);
    }

    /// Large packet spanning multiple blocks.
    #[test]
    fn multi_block_roundtrip() {
        let enc_keys = SERVER_ENCRYPT;
        let dec_keys = CLIENT_DECRYPT;

        // 3 header bytes (C4), then 30 data bytes → 33 total.
        let mut plain = vec![0xC4, 0x00, 0x21]; // big-endian len = 33
        plain.extend(0u8..30u8);

        let mut enc_ctr = 0u8;
        let encrypted = encrypt(&plain, &enc_keys, &mut enc_ctr);
        assert_eq!(encrypted[0], 0xC4);

        let mut dec_ctr = 0u8;
        let decrypted = decrypt(&encrypted, &dec_keys, &mut dec_ctr).unwrap();
        assert_eq!(decrypted, plain);
    }
}
