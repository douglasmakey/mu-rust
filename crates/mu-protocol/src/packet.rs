use crate::{
    error::ProtocolError,
    protocol_constants::{C1, C2, C3, C4},
};
use anyhow::Result;
use bytes::Bytes;

/// MU Online protocol packet types.
///
/// The first byte of every packet determines both the header size and
/// whether the body is encrypted.
/// See: docs/OpenMU/Packets/PacketTypes.md
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RawPacketType {
    C1,
    C2,
    C3,
    C4,
}

impl RawPacketType {
    pub fn header_length(self) -> usize {
        match self {
            Self::C1 | Self::C3 => 2,
            Self::C2 | Self::C4 => 3,
        }
    }

    pub fn is_encrypted(self) -> bool {
        matches!(self, Self::C3 | Self::C4)
    }
}

impl TryFrom<u8> for RawPacketType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            C1 => Ok(Self::C1),
            C2 => Ok(Self::C2),
            C3 => Ok(Self::C3),
            C4 => Ok(Self::C4),
            _ => Err(ProtocolError::InvalidHeader(value)),
        }
    }
}

/// A validated, immutable MU protocol packet.
///
/// Construction through `try_new` / `try_from_vec` enforces these invariants:
/// - The first byte is a valid header (C1/C2/C3/C4).
/// - The buffer is at least `header_length` bytes long.
/// - The declared length field matches the actual buffer length.
///
/// `packet_type` is cached at construction so accessors are infallible.
pub struct RawPacket {
    bytes: Bytes,
    packet_type: RawPacketType,
}

impl RawPacket {
    pub fn try_from_vec(bytes: Vec<u8>) -> Result<Self, ProtocolError> {
        Self::try_new(Bytes::from(bytes))
    }

    /// Creates a validated `RawPacket`, checking that the declared length matches the actual length.
    pub fn try_new(bytes: Bytes) -> Result<Self, ProtocolError> {
        let declared_len =
            declared_length_from_prefix(bytes.as_ref())?.ok_or(ProtocolError::Incomplete)?;
        let actual_len = bytes.len();
        if declared_len != actual_len {
            return Err(ProtocolError::LengthMismatch {
                declared: declared_len,
                actual: actual_len,
            });
        }

        let packet_type = bytes[0].try_into()?;
        Ok(Self { bytes, packet_type })
    }

    pub fn packet_type(&self) -> RawPacketType {
        self.packet_type
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// Returns `(code, sub_code)` from the bytes immediately after the header.
    ///
    /// For a C1 packet `[C1, len, code, sub_code, ...]` these are at indices 2 and 3.
    /// For a C2 packet `[C2, len_hi, len_lo, code, sub_code, ...]` they are at 3 and 4.
    ///
    /// Either field is `None` if the packet is too short to contain it (a header-only
    /// packet is structurally valid but carries no code).
    pub fn header_codes(&self) -> (Option<u8>, Option<u8>) {
        let header_len = self.packet_type.header_length();
        (
            self.bytes.get(header_len).copied(),
            self.bytes.get(header_len + 1).copied(),
        )
    }
}

impl std::fmt::Debug for RawPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RawPacket(len={}, bytes={:02X?})",
            self.bytes.len(),
            self.bytes.as_ref()
        )
    }
}

/// Parses the declared packet length from a (possibly partial) byte slice.
///
/// Used by both `PacketCodec::decode` (stream framing) and `RawPacket::try_new`
/// (construction validation) so the length-parsing logic lives in one place.
///
/// Returns:
/// - `Ok(None)` — not enough bytes yet to determine the length (caller should wait for more data).
/// - `Ok(Some(n))` — the packet declares itself to be `n` bytes total.
/// - `Err(InvalidHeader)` — the first byte is not a recognized packet type.
/// - `Err(InvalidLength)` — the declared length is smaller than the header itself.
pub fn declared_length_from_prefix(bytes: &[u8]) -> Result<Option<usize>, ProtocolError> {
    let Some(&packet_type_b) = bytes.first() else {
        return Ok(None);
    };

    let packet_type: RawPacketType = packet_type_b.try_into()?;
    let header_len = packet_type.header_length();
    if bytes.len() < header_len {
        return Ok(None);
    }

    // C1/C3: single-byte length at index 1 (max 255).
    // C2/C4: two-byte big-endian length at indices 1 and 2 (max 65535).
    let declared_len = match packet_type {
        RawPacketType::C1 | RawPacketType::C3 => bytes[1] as usize,
        RawPacketType::C2 | RawPacketType::C4 => ((bytes[1] as usize) << 8) | (bytes[2] as usize),
    };

    if declared_len < header_len {
        return Err(ProtocolError::InvalidLength {
            declared: declared_len,
            minimum: header_len,
        });
    }

    Ok(Some(declared_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_length() {
        assert_eq!(RawPacketType::C1.header_length(), 2);
        assert_eq!(RawPacketType::C2.header_length(), 3);
        assert_eq!(RawPacketType::C3.header_length(), 2);
        assert_eq!(RawPacketType::C4.header_length(), 3);
    }

    #[test]
    fn test_is_encrypted() {
        assert!(!RawPacketType::C1.is_encrypted());
        assert!(!RawPacketType::C2.is_encrypted());
        assert!(RawPacketType::C3.is_encrypted());
        assert!(RawPacketType::C4.is_encrypted());
    }

    #[test]
    fn declared_length_from_c1_prefix() {
        let declared = declared_length_from_prefix(&[0xC1, 0x04, 0x00, 0x01]).unwrap();
        assert_eq!(declared, Some(4));
    }

    #[test]
    fn try_new_rejects_length_mismatch() {
        let packet = RawPacket::try_new(Bytes::from_static(&[0xC1, 0x05, 0x00, 0x01]));
        assert!(matches!(
            packet,
            Err(ProtocolError::LengthMismatch {
                declared: 5,
                actual: 4
            })
        ));
    }

    // --- declared_length_from_prefix ---

    #[test]
    fn declared_length_c2_big_endian_two_byte_length() {
        // C2 length field spans bytes 1–2 in big-endian; verify the shift is correct.
        let declared =
            declared_length_from_prefix(&[C2, 0x00, 0x07, 0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
        assert_eq!(declared, Some(7));
    }

    #[test]
    fn declared_length_incomplete_returns_none() {
        assert_eq!(declared_length_from_prefix(&[]).unwrap(), None);
        // C2 needs two length bytes; only one provided.
        assert_eq!(declared_length_from_prefix(&[C2, 0x00]).unwrap(), None);
    }

    #[test]
    fn declared_length_too_small_returns_error() {
        // Declared length smaller than its own header is structurally impossible.
        assert!(matches!(
            declared_length_from_prefix(&[C1, 0x01]),
            Err(ProtocolError::InvalidLength {
                declared: 1,
                minimum: 2
            })
        ));
    }

    // --- RawPacket construction ---

    #[test]
    fn try_new_empty_buffer_returns_incomplete() {
        assert!(matches!(
            RawPacket::try_new(Bytes::new()),
            Err(ProtocolError::Incomplete)
        ));
    }

    // --- RawPacket::header_codes ---

    #[test]
    fn header_codes_c2_offset_is_three() {
        // C2 header is 3 bytes so code/sub_code sit at indices 3 and 4, not 2 and 3.
        let packet = RawPacket::try_from_vec(vec![C2, 0x00, 0x05, 0xF4, 0x06]).unwrap();
        assert_eq!(packet.header_codes(), (Some(0xF4), Some(0x06)));
    }
}
