use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};

use crate::{
    error::ProtocolError,
    packet::{RawPacket, declared_length_from_prefix},
};

/// Stateless codec that frames a TCP byte stream into validated `RawPacket`s.
///
/// Responsibilities are split:
/// - **This codec**: stream framing — wait until enough bytes are buffered for a complete frame.
/// - **`RawPacket::try_new`**: structural validation — header type, declared vs actual length.
pub struct PacketCodec;

impl Decoder for PacketCodec {
    type Item = RawPacket;
    type Error = ProtocolError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(declared_len) = declared_length_from_prefix(src.as_ref())? else {
            return Ok(None);
        };

        if src.len() < declared_len {
            // Tell tokio-util how many bytes we still need so it can size
            // the next read syscall appropriately.
            src.reserve(declared_len - src.len());
            return Ok(None);
        }

        // split_to advances the buffer past this frame; freeze yields an
        // immutable Bytes (zero-copy, Arc-backed) for RawPacket to own.
        let packet = src.split_to(declared_len).freeze();
        Ok(Some(RawPacket::try_new(packet)?))
    }
}

impl Encoder<RawPacket> for PacketCodec {
    type Error = ProtocolError;

    fn encode(&mut self, item: RawPacket, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend_from_slice(item.as_slice());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol_constants::{C1, C2};

    use super::*;

    #[test]
    fn decode_c1_packet() {
        let mut codec = PacketCodec;
        let mut buf = BytesMut::from(&[C1, 0x04, 0x00, 0x01][..]);
        let packet = codec.decode(&mut buf).unwrap().unwrap();

        assert_eq!(packet.as_slice(), [0xC1, 0x04, 0x00, 0x01]);
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_c2_packet() {
        let mut codec = PacketCodec;
        let mut buf = BytesMut::from(&[C2, 0x00, 0x07, 0xF4, 0x06, 0x00, 0x00][..]);
        let packet = codec.decode(&mut buf).unwrap().unwrap();

        assert_eq!(packet.len(), 7);
        let (code, sub_code) = packet.header_codes();
        assert_eq!(code, Some(0xF4));
        assert_eq!(sub_code, Some(0x06))
    }

    #[test]
    fn incomplete_packet_returns_none() {
        let mut codec = PacketCodec;
        let mut buf = BytesMut::from(&[0xC1, 0x05, 0x00][..]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn decode_two_consecutive_packets_from_same_buffer() {
        // The codec must advance the buffer cursor correctly so the second
        // call yields the next frame, not a re-read of the first.
        let mut codec = PacketCodec;
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
        use crate::error::ProtocolError;
        let mut codec = PacketCodec;
        let mut buf = BytesMut::from(&[0x00, 0x04, 0x00, 0x01][..]);
        assert!(matches!(
            codec.decode(&mut buf),
            Err(ProtocolError::InvalidHeader(0x00))
        ));
    }

    #[test]
    fn encode_round_trips_packet_bytes() {
        let mut codec = PacketCodec;
        let packet = RawPacket::try_from_vec(vec![C1, 0x04, 0xF4, 0x06]).unwrap();
        let mut dst = BytesMut::new();
        codec.encode(packet, &mut dst).unwrap();
        assert_eq!(dst.as_ref(), &[C1, 0x04, 0xF4, 0x06]);
    }
}
