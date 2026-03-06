const DEFAULT_XOR3_KEY: [u8; 3] = [0xFC, 0xCF, 0xAB];

fn apply_xor3_in_place(data: &mut [u8]) {
    for (index, byte) in data.iter_mut().enumerate() {
        *byte ^= DEFAULT_XOR3_KEY[index % 3]
    }
}

pub fn encrypt_xor3(data: &mut [u8]) {
    apply_xor3_in_place(data);
}

pub fn decrypt_xor3(data: &mut [u8]) {
    apply_xor3_in_place(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor3() {
        let mut payload = b"mu-rust".to_vec();
        encrypt_xor3(&mut payload);
        assert_ne!(payload, b"mu-rust");

        decrypt_xor3(&mut payload);
        assert_eq!(payload, b"mu-rust");
    }
}
