use crate::error::{ParseError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum PacketType {
    SignalDataWithStreamId = 0x1,
    ContextWithStreamId = 0x4,
    CommandWithStreamId = 0x6,
    ExtensionCommandWithStreamId = 0x7,
}

impl TryFrom<u8> for PacketType {
    type Error = ParseError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x1 => Ok(Self::SignalDataWithStreamId),
            0x4 => Ok(Self::ContextWithStreamId),
            0x6 => Ok(Self::CommandWithStreamId),
            0x7 => Ok(Self::ExtensionCommandWithStreamId),
            value => Err(ParseError::UnsupportedPacketType { value }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum Tsi {
    Utc = 0x1,
    Gps = 0x2,
    Posix = 0x3,
}

impl TryFrom<u8> for Tsi {
    type Error = ParseError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x1 => Ok(Self::Utc),
            0x2 => Ok(Self::Gps),
            0x3 => Ok(Self::Posix),
            value => Err(ParseError::InvalidTsi { value }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum Tsf {
    SampleCount = 0x1,
    RealTimePicoseconds = 0x2,
}

impl TryFrom<u8> for Tsf {
    type Error = ParseError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x1 => Ok(Self::SampleCount),
            0x2 => Ok(Self::RealTimePicoseconds),
            value => Err(ParseError::InvalidTsf { value }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum TimestampMode {
    Fine = 0,
    Coarse = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PacketHeader {
    pub raw: u32,
    pub packet_type: PacketType,
    pub class_id_indicator: bool,
    pub type_specific_bits: u8,
    pub tsm: Option<TimestampMode>,
    pub tsi: Tsi,
    pub tsf: Tsf,
    pub sequence: u8,
    pub packet_size_words: u16,
}

impl PacketHeader {
    pub(crate) fn parse(raw: u32) -> Result<Self> {
        let packet_type = PacketType::try_from(((raw >> 28) & 0xF) as u8)?;
        let class_id_indicator = ((raw >> 27) & 0x1) == 1;
        let type_specific_bits = ((raw >> 24) & 0x7) as u8;
        let tsi = Tsi::try_from(((raw >> 22) & 0x3) as u8)?;
        let tsf = Tsf::try_from(((raw >> 20) & 0x3) as u8)?;
        let sequence = ((raw >> 16) & 0xF) as u8;
        let packet_size_words = (raw & 0xFFFF) as u16;
        let tsm = match packet_type {
            PacketType::ContextWithStreamId => {
                if (type_specific_bits & 0b001) == 1 {
                    Some(TimestampMode::Coarse)
                } else {
                    Some(TimestampMode::Fine)
                }
            }
            _ => None,
        };

        Ok(Self {
            raw,
            packet_type,
            class_id_indicator,
            type_specific_bits,
            tsm,
            tsi,
            tsf,
            sequence,
            packet_size_words,
        })
    }
}
