use bytes::{Buf, BufMut, Bytes};
use std::convert::TryFrom;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HeaderError {
    #[error("buffer too short")]
    BufferTooShort,
    #[error("invalid cid length")]
    InvalidCidLength,
    #[error("invalid packet type")]
    InvalidPacketType,
}

/// QUIC Version Number(u32)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version(pub u32);

/// Connection ID (0..=20 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionId {
    pub cid: Bytes,
}
impl ConnectionId {
    pub fn empty() -> Self {
        Self { cid: Bytes::new() }
    }
    pub fn len(&self) -> usize {
        self.cid.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LongPacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    VersionNegotiation,
}

impl TryFrom<u8> for LongPacketType {
    type Error = HeaderError;
    fn try_from(b: u8) -> Result<Self, Self::Error> {
        match b & 0x7F {
            0x00 => Ok(Self::Initial),
            0x01 => Ok(Self::ZeroRtt),
            0x02 => Ok(Self::Handshake),
            0x03 => Ok(Self::Retry),
            _ => Err(HeaderError::InvalidPacketType),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongHeader {
    pub packet_type: LongPacketType,
    pub version: Version,
    pub dst_cid: ConnectionId,
    pub src_cid: ConnectionId,
    pub packet_number: u32,
    pub payload: Bytes,
}

impl TryFrom<&[u8]> for LongHeader {
    type Error = HeaderError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let mut r = Bytes::copy_from_slice(buf);
        if r.remaining() < 1 {
            return Err(HeaderError::BufferTooShort);
        }

        let first = r.get_u8();
        // The highest bit must be 1.
        if first >> 7 != 1 {
            return Err(HeaderError::InvalidPacketType);
        }
        let packet_type = LongPacketType::try_from(first)?;

        if r.remaining() < 4 {
            return Err(HeaderError::BufferTooShort);
        }
        let version = Version(r.get_u32());

        // DCID
        let dc_len = r.get_u8() as usize;
        if r.remaining() < dc_len {
            return Err(HeaderError::BufferTooShort);
        }
        let dst_cid = ConnectionId {
            cid: r.copy_to_bytes(dc_len),
        };

        // SCID
        let sc_len = r.get_u8() as usize;
        if r.remaining() < sc_len {
            return Err(HeaderError::BufferTooShort);
        }
        let src_cid = ConnectionId {
            cid: r.copy_to_bytes(sc_len),
        };

        // Packet Number（IETF QUIC Long header must be 32 bits.)
        if r.remaining() < 4 {
            return Err(HeaderError::BufferTooShort);
        }
        let packet_number = r.get_u32();

        // Rest of bits are payload.
        let payload = r.copy_to_bytes(r.remaining());

        Ok(Self {
            packet_type,
            version,
            dst_cid,
            src_cid,
            packet_number,
            payload,
        })
    }
}

impl LongHeader {
    /// Write into BufMut
    pub fn write<B: BufMut>(&self, buf: &mut B) {
        let type_byte = match self.packet_type {
            LongPacketType::Initial => 0x00,
            LongPacketType::ZeroRtt => 0x01,
            LongPacketType::Handshake => 0x02,
            LongPacketType::Retry => 0x03,
            LongPacketType::VersionNegotiation => 0x00,
        };
        buf.put_u8(0x80 | type_byte);
        buf.put_u32(self.version.0);
        buf.put_u8(self.dst_cid.len() as u8);
        buf.put_slice(&self.dst_cid.cid);
        buf.put_u8(self.src_cid.len() as u8);
        buf.put_slice(&self.src_cid.cid);
        buf.put_u32(self.packet_number);
        buf.put_slice(&self.payload);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortHeader {
    pub key_phase: bool,
    pub dst_cid: ConnectionId,
    pub packet_number: u64,
    pub payload: Bytes,
}

impl TryFrom<&[u8]> for ShortHeader {
    type Error = HeaderError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let mut r = Bytes::copy_from_slice(buf);
        if r.remaining() < 1 {
            return Err(HeaderError::BufferTooShort);
        }

        let first = r.get_u8();
        if first >> 7 != 0 {
            return Err(HeaderError::InvalidPacketType);
        }

        let key_phase = (first & 0x40) != 0;
        let pn_len = ((first >> 4) & 0x03) as usize + 1; // 1,2,4 字节
        let cid_len = r.get_u8() as usize; // QUIC 标准中短 header 没有 cid_len 字节，这里简化
        let dst_cid = ConnectionId {
            cid: r.copy_to_bytes(cid_len),
        };

        if r.remaining() < pn_len {
            return Err(HeaderError::BufferTooShort);
        }
        let pn = match pn_len {
            1 => r.get_u8() as u64,
            2 => r.get_u16() as u64,
            4 => r.get_u32() as u64,
            _ => unreachable!(),
        };

        let payload = r.copy_to_bytes(r.remaining());
        Ok(Self {
            key_phase,
            dst_cid,
            packet_number: pn,
            payload,
        })
    }
}

impl ShortHeader {
    pub fn write<B: BufMut>(&self, buf: &mut B) {
        let mut first = 0x00u8; // Header Form = 0
        if self.key_phase {
            first |= 0x40;
        }

        let pn = self.packet_number;
        let (pn_len, pn_bytes): (usize, &[u8]) = if pn < (1 << 8) {
            first |= 0x00;
            (1, &(pn as u8).to_be_bytes())
        } else if pn < (1 << 16) {
            first |= 0x10;
            (2, &(pn as u16).to_be_bytes())
        } else {
            first |= 0x30;
            (4, &(pn as u32).to_be_bytes())
        };
        buf.put_u8(first);
        buf.put_u8(self.dst_cid.len() as u8);
        buf.put_slice(&self.dst_cid.cid);
        buf.put_slice(&pn_bytes[..pn_len]);
        buf.put_slice(&self.payload);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn round_trip_long() {
        let hdr = LongHeader {
            packet_type: LongPacketType::Initial,
            version: Version(0x00000001),
            dst_cid: ConnectionId {
                cid: Bytes::from_static(&[1, 2, 3, 4]),
            },
            src_cid: ConnectionId {
                cid: Bytes::from_static(&[5, 6]),
            },
            packet_number: 0x12345678,
            payload: Bytes::from_static(b"hello"),
        };
        let mut buf = BytesMut::new();
        hdr.write(&mut buf);
        let parsed = LongHeader::try_from(&buf[..]).unwrap();
        assert_eq!(hdr, parsed);
    }

    #[test]
    fn round_trip_short() {
        let hdr = ShortHeader {
            key_phase: true,
            dst_cid: ConnectionId {
                cid: Bytes::from_static(&[9, 8, 7]),
            },
            packet_number: 42,
            payload: Bytes::from_static(b"world"),
        };
        let mut buf = BytesMut::new();
        hdr.write(&mut buf);
        let parsed = ShortHeader::try_from(&buf[..]).unwrap();
        assert_eq!(hdr, parsed);
    }
}
