pub mod simple_modulus;
pub mod xor3;
pub mod xor32;

fn header_size(packet_type: u8) -> usize {
    match packet_type {
        0xC1 | 0xC3 => 2,
        0xC2 | 0xC4 => 3,
        _ => 0,
    }
}
