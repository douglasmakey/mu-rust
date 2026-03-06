use crate::{
    crypto::{
        simple_modulus::{self, SERVER_DECRYPT, SERVER_ENCRYPT},
        xor32::decrypt_xor32,
    },
    error::ProtocolError,
    packet::{RawPacket, declared_length_from_prefix},
};
use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug, Clone)]
pub enum EncryptionMode {
    /// No encryption — packets are framed and forwarded as-is (connect-server).
    None,
    /// Game-server mode.
    ///
    /// **Encode** (server → client): SimpleModulus for C3/C4; C1/C2 unchanged.
    /// **Decode** (client → server): two-stage pipeline matching OpenMU's implementation:
    /// 1. SimpleModulus — decrypts C3/C4; C1/C2 pass through.
    /// 2. XOR32 — applied to all packet types after stage 1.
    SimpleModulusPlusXOR32,
}

/// Stateful codec that frames a TCP byte stream into validated [`RawPacket`]s
/// and optionally encrypts / decrypts them.
///
/// Responsibilities are split:
/// - **This codec**: stream framing — wait until enough bytes are buffered for a complete frame.
/// - **[`RawPacket::try_new`]**: structural validation — header type, declared vs actual length.
///
/// For [`EncryptionMode::SimpleModulusPlusXOR32`], `decrypt_counter` and `encrypt_counter`
/// are incremented automatically with each C3/C4 packet.
pub struct PacketCodec {
    max_packet_size: usize,
    mode: EncryptionMode,
    decrypt_counter: u8,
    encrypt_counter: u8,
}

impl PacketCodec {
    pub fn new(max_packet_size: usize, mode: EncryptionMode) -> Self {
        Self {
            max_packet_size,
            mode,
            decrypt_counter: 0,
            encrypt_counter: 0,
        }
    }
}

impl Decoder for PacketCodec {
    type Item = RawPacket;
    type Error = ProtocolError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(declared_len) = declared_length_from_prefix(src.as_ref())? else {
            return Ok(None);
        };

        if declared_len > self.max_packet_size {
            return Err(ProtocolError::PacketTooLarge {
                max: self.max_packet_size,
                actual: declared_len,
            });
        }

        if src.len() < declared_len {
            // Tell tokio-util how many bytes we still need so it can size
            // the next read syscall appropriately.
            src.reserve(declared_len - src.len());
            return Ok(None);
        }

        let raw = src.split_to(declared_len);
        let packet = match self.mode {
            EncryptionMode::None => raw.freeze(),
            EncryptionMode::SimpleModulusPlusXOR32 => {
                // Stage 1 – SimpleModulus: decrypt C3/C4; C1/C2 pass through.
                let after_sm: BytesMut = if raw[0] >= 0xC3 {
                    let decrypted = simple_modulus::decrypt(
                        raw.as_ref(),
                        &SERVER_DECRYPT,
                        &mut self.decrypt_counter,
                    )
                    .map_err(|e| ProtocolError::Decryption(e.to_string()))?;

                    BytesMut::from(decrypted.as_slice())
                } else {
                    raw
                };

                // Stage 2 – XOR32: applied to all packet types.
                let mut buf = after_sm;
                decrypt_xor32(&mut buf);
                buf.freeze()
            }
        };

        Ok(Some(RawPacket::try_new(packet)?))
    }
}

impl Encoder<RawPacket> for PacketCodec {
    type Error = ProtocolError;

    fn encode(&mut self, item: RawPacket, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match self.mode {
            EncryptionMode::None => dst.extend_from_slice(item.as_slice()),
            EncryptionMode::SimpleModulusPlusXOR32 => {
                // Server → client: C3/C4 use SimpleModulus only; C1/C2 are clear.
                if item.packet_type().is_encrypted() {
                    let encrypted = simple_modulus::encrypt(
                        item.as_slice(),
                        &SERVER_ENCRYPT,
                        &mut self.encrypt_counter,
                    );
                    dst.extend_from_slice(&encrypted);
                } else {
                    dst.extend_from_slice(item.as_slice());
                }
            }
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{
            simple_modulus::{CLIENT_DECRYPT, CLIENT_ENCRYPT, decrypt, encrypt},
            xor32::encrypt_xor32,
        },
        protocol_constants::{C1, C2, C3},
    };

    fn no_enc_codec() -> PacketCodec {
        PacketCodec::new(1024, EncryptionMode::None)
    }

    fn game_server_codec() -> PacketCodec {
        PacketCodec::new(4096, EncryptionMode::SimpleModulusPlusXOR32)
    }

    // ── No-encryption baseline tests ─────────────────────────────────────────

    #[test]
    fn decode_c1_packet() {
        let mut codec = no_enc_codec();
        let mut buf = BytesMut::from(&[C1, 0x04, 0x00, 0x01][..]);
        let packet = codec.decode(&mut buf).unwrap().unwrap();

        assert_eq!(packet.as_slice(), [0xC1, 0x04, 0x00, 0x01]);
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_c2_packet() {
        let mut codec = no_enc_codec();
        let mut buf = BytesMut::from(&[C2, 0x00, 0x07, 0xF4, 0x06, 0x00, 0x00][..]);
        let packet = codec.decode(&mut buf).unwrap().unwrap();

        assert_eq!(packet.len(), 7);
        let (code, sub_code) = packet.header_codes();
        assert_eq!(code, Some(0xF4));
        assert_eq!(sub_code, Some(0x06))
    }

    #[test]
    fn incomplete_packet_returns_none() {
        let mut codec = no_enc_codec();
        let mut buf = BytesMut::from(&[0xC1, 0x05, 0x00][..]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn decode_two_consecutive_packets_from_same_buffer() {
        let mut codec = no_enc_codec();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[C1, 0x04, 0xF4, 0x06]);
        buf.extend_from_slice(&[C1, 0x04, 0xAA, 0xBB]);

        let first = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(first.as_slice(), [C1, 0x04, 0xF4, 0x06]);

        let second = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(second.as_slice(), [C1, 0x04, 0xAA, 0xBB]);
    }

    #[test]
    fn decode_invalid_header_returns_error() {
        let mut codec = no_enc_codec();
        let mut buf = BytesMut::from(&[0x00, 0x04, 0x00, 0x01][..]);
        assert!(matches!(
            codec.decode(&mut buf),
            Err(ProtocolError::InvalidHeader(0x00))
        ));
    }

    #[test]
    fn encode_round_trips_packet_bytes() {
        let mut codec = no_enc_codec();
        let packet = RawPacket::try_from_vec(vec![C1, 0x04, 0xF4, 0x06]).unwrap();
        let mut dst = BytesMut::new();
        codec.encode(packet, &mut dst).unwrap();
        assert_eq!(dst.as_ref(), &[C1, 0x04, 0xF4, 0x06]);
    }

    // ── SimpleModulus encode (server → client) ────────────────────────────────

    /// Server-side encoder applies SimpleModulus to C3/C4 only.
    /// The result must be decodable by a plain SimpleModulus call (no XOR32),
    /// which is what a real client would do.
    #[test]
    fn server_encodes_c3_with_simple_modulus_only() {
        let plain = vec![C3, 0x06, 0xF3, 0x00, 0x01, 0x02];
        let packet = RawPacket::try_from_vec(plain.clone()).unwrap();

        let mut encoder = game_server_codec();
        let mut wire = BytesMut::new();
        encoder.encode(packet, &mut wire).unwrap();

        // SimpleModulus expands the packet.
        assert!(wire.len() > plain.len());
        assert_eq!(wire[0], C3);

        // A client decodes with CLIENT_DECRYPT_KEYS and no XOR32.
        let mut ctr = 0u8;
        let decrypted = decrypt(wire.as_ref(), &CLIENT_DECRYPT, &mut ctr).unwrap();
        assert_eq!(decrypted, plain);
    }

    /// C1 packets are forwarded without any transformation.
    #[test]
    fn server_encodes_c1_unchanged() {
        let plain = vec![C1, 0x04, 0xAA, 0xBB];
        let packet = RawPacket::try_from_vec(plain.clone()).unwrap();

        let mut encoder = game_server_codec();
        let mut wire = BytesMut::new();
        encoder.encode(packet, &mut wire).unwrap();

        assert_eq!(wire.as_ref(), plain.as_slice());
    }

    // ── SimpleModulus decode (client → server) ────────────────────────────────

    /// Server-side decoder recovers a C3 packet encoded by the client as
    /// XOR32(plaintext) → SimpleModulus — the two-stage pipeline from OpenMU.
    #[test]
    fn server_decodes_c3_from_client() {
        let plain = vec![C3, 0x06, 0xF3, 0x00, 0x01, 0x02];

        // Client stage 1: XOR32 the plaintext.
        let mut xored = plain.clone();
        encrypt_xor32(&mut xored);

        // Client stage 2: SimpleModulus encrypt the XOR32'd packet.
        let mut ctr = 0u8;
        let wire = encrypt(&xored, &CLIENT_ENCRYPT, &mut ctr);

        let mut decoder = game_server_codec();
        let mut buf = BytesMut::from(wire.as_slice());
        let decoded = decoder.decode(&mut buf).unwrap().unwrap();

        assert_eq!(decoded.as_slice(), plain.as_slice());
    }

    /// Server-side decoder applies XOR32-only to a C1 packet sent by the client.
    #[test]
    fn server_decodes_c1_from_client() {
        let plain = vec![C1, 0x05, 0xAA, 0xBB, 0xCC];

        // Client: XOR32 only for C1/C2.
        let mut wire = plain.clone();
        encrypt_xor32(&mut wire);

        // Header bytes (type, length) must survive XOR32 for correct framing.
        assert_eq!(wire[0], C1);
        assert_eq!(wire[1], 0x05);

        let mut decoder = game_server_codec();
        let mut buf = BytesMut::from(wire.as_slice());
        let decoded = decoder.decode(&mut buf).unwrap().unwrap();

        assert_eq!(decoded.as_slice(), plain.as_slice());
    }

    /// Multiple sequential C3 packets: counters on both sides must stay in sync.
    #[test]
    fn server_decodes_multiple_c3_packets_in_sequence() {
        let mut decoder = game_server_codec();
        let enc_keys = CLIENT_ENCRYPT;

        let mut client_ctr = 0u8;

        for i in 0u8..4 {
            let plain = vec![C3, 0x05, 0xF0, 0x01, i];

            // Client: XOR32 first, then SimpleModulus.
            let mut xored = plain.clone();
            encrypt_xor32(&mut xored);
            let wire = encrypt(&xored, &enc_keys, &mut client_ctr);

            let mut buf = BytesMut::from(wire.as_slice());
            let decoded = decoder.decode(&mut buf).unwrap().unwrap();
            assert_eq!(
                decoded.as_slice(),
                plain.as_slice(),
                "mismatch at packet {i}"
            );
        }
        assert_eq!(client_ctr, 4);
        assert_eq!(decoder.decrypt_counter, 4);
    }

    /// Verify the exact bytes from the bug report: after our two-stage decode
    /// the subcode at byte 3 must be 0x01, not 0x0E.
    #[test]
    fn login_packet_subcode_is_correct_after_decode() {
        // Simulate what the client puts on the wire for a C3 F1-01 login packet.
        // We use a minimal 4-byte body: [F1, 01, 00, 00].
        let plain = vec![C3, 0x06, 0xF1, 0x01, 0x00, 0x00];

        let mut xored = plain.clone();
        encrypt_xor32(&mut xored);

        let mut ctr = 0u8;
        let wire = encrypt(&xored, &CLIENT_ENCRYPT, &mut ctr);

        let mut decoder = game_server_codec();
        let mut buf = BytesMut::from(wire.as_slice());
        let decoded = decoder.decode(&mut buf).unwrap().unwrap();

        assert_eq!(decoded.as_slice(), plain.as_slice());
        assert_eq!(decoded.as_slice()[2], 0xF1, "code");
        assert_eq!(decoded.as_slice()[3], 0x01, "subcode");
    }
}
