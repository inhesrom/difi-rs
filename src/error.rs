use crate::{InformationClassCode, PacketClassCode, PacketType, Tsf, Tsi};
use thiserror::Error;

pub type Result<T> = core::result::Result<T, ParseError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ParseError {
    #[error("input too short: need at least {min} bytes, got {actual}")]
    InputTooShort { min: usize, actual: usize },

    #[error("packet size is too small: {words} words")]
    PacketSizeTooSmall { words: u16 },

    #[error("packet is truncated: need {needed} bytes, got {actual}")]
    PacketTruncated { needed: usize, actual: usize },

    #[error("trailing bytes after exact DIFI packet: {trailing} bytes")]
    TrailingBytes { trailing: usize },

    #[error("unsupported packet type 0x{value:X}")]
    UnsupportedPacketType { value: u8 },

    #[error("class identifier indicator is not set")]
    MissingClassId,

    #[error("{field} reserved bits are non-zero: 0x{bits:X}")]
    ReservedBitsNonZero { field: &'static str, bits: u32 },

    #[error("invalid DIFI CID/OUI: 0x{actual:06X}")]
    InvalidOui { actual: u32 },

    #[error("invalid TSI code {value}")]
    InvalidTsi { value: u8 },

    #[error("invalid TSF code {value}")]
    InvalidTsf { value: u8 },

    #[error("unknown information class 0x{value:04X}")]
    UnknownInformationClass { value: u16 },

    #[error("unknown packet class 0x{value:04X}")]
    UnknownPacketClass { value: u16 },

    #[error(
        "packet class {packet_class:?} is not valid for information class {information_class:?}"
    )]
    PacketClassNotInInformationClass {
        information_class: InformationClassCode,
        packet_class: PacketClassCode,
    },

    #[error("packet type {packet_type:?} is not valid for packet class {packet_class:?}")]
    PacketTypeClassMismatch {
        packet_type: PacketType,
        packet_class: PacketClassCode,
    },

    #[error("packet class {packet_class:?} requires TSF {expected:?}, got {actual:?}")]
    InvalidTsfForPacketClass {
        packet_class: PacketClassCode,
        expected: Tsf,
        actual: Tsf,
    },

    #[error("packet class {packet_class:?} rejects TSI {actual:?}")]
    InvalidTsiForPacketClass {
        packet_class: PacketClassCode,
        actual: Tsi,
    },

    #[error("{field} header bits 0x{actual:X} do not match expected 0x{expected:X}")]
    InvalidHeaderBits {
        field: &'static str,
        expected: u8,
        actual: u8,
    },

    #[error("{packet_class:?} expected {expected} words, got {actual}")]
    InvalidPacketSize {
        packet_class: PacketClassCode,
        expected: u16,
        actual: u16,
    },

    #[error("{packet_class:?} expected one of {expected:?} words, got {actual}")]
    InvalidPacketSizeSet {
        packet_class: PacketClassCode,
        expected: &'static [u16],
        actual: u16,
    },

    #[error(
        "non-zero pad bit count {pad_bit_count} is not permitted for {information_class:?}/{packet_class:?}"
    )]
    PadBitsNotAllowed {
        information_class: InformationClassCode,
        packet_class: PacketClassCode,
        pad_bit_count: u8,
    },

    #[error("pad bit count {pad_bit_count} exceeds payload bit length {payload_bits}")]
    InvalidPadding {
        pad_bit_count: u8,
        payload_bits: usize,
    },

    #[error("padding bits in final payload word are non-zero")]
    NonZeroPaddingBits,

    #[error("{field} value 0x{actual:08X} does not match expected 0x{expected:08X}")]
    InvalidFieldValue {
        field: &'static str,
        expected: u32,
        actual: u32,
    },

    #[error("{field} value 0x{actual:08X} is not one of the allowed values")]
    InvalidFieldValueSet { field: &'static str, actual: u32 },

    #[error("invalid payload format words: 0x{word0:08X} 0x{word1:08X}")]
    InvalidPayloadFormat { word0: u32, word1: u32 },

    #[error("{field} fixed-point value has non-zero fractional bits: 0x{raw:016X}")]
    FractionalHzNotAllowed { field: &'static str, raw: u64 },
}
