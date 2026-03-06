use crate::crypto::header_size;

pub const XOR32_KEY: [u8; 32] = [
    0xAB, 0x11, 0xCD, 0xFE, 0x18, 0x23, 0xC5, 0xA3, 0xCA, 0x33, 0xC1, 0xCC, 0x66, 0x67, 0x21, 0xF3,
    0x32, 0x12, 0x15, 0x35, 0x29, 0xFF, 0xFE, 0x1D, 0x44, 0xEF, 0xCD, 0x41, 0x26, 0x3C, 0x4E, 0x4D,
];

pub fn encrypt_xor32(data: &mut [u8]) {
    let header_size = header_size(data[0]);
    for i in header_size + 1..data.len() {
        // Start from header_size + 1 because encryption uses result[i-1]
        data[i] = data[i] ^ data[i - 1] ^ XOR32_KEY[i % 32];
    }
}

pub fn decrypt_xor32(data: &mut [u8]) {
    let header_size = header_size(data[0]);
    for i in (header_size + 1..data.len()).rev() {
        // Start from header_size + 1 because encryption uses result[i-1]
        data[i] = data[i] ^ data[i - 1] ^ XOR32_KEY[i % 32];
    }
}
