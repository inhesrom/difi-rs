#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod class_id;
mod command;
mod context;
mod data;
mod error;
mod header;
mod information;
mod packet;
mod parser;
mod payload_format;
mod raw;
mod samples;
mod sequence;
mod validation;
mod version;

#[cfg(feature = "write")]
pub mod writer;

pub use class_id::{ClassId, DIFI_CID};
pub use command::{
    BufferStatus, CapabilityForm, CommandCommon, ReferenceLevelLimit, SinkCapabilitiesQueryPacket,
    SinkCapabilitiesResponsePacket, StatusReportPacket, TimingFlowControlPacket,
};
pub use context::{FixedI64, FixedU64, SignalContextPacket};
pub use data::SignalDataPacket;
pub use error::{ParseError, Result};
pub use header::{PacketHeader, PacketType, TimestampMode, Tsf, Tsi};
pub use information::{InformationClassCode, PacketClassCode};
pub use packet::{Packet, Prologue};
pub use payload_format::{PayloadFormat, PayloadSampleFormat};
pub use samples::{
    ComplexI8, ComplexI16, IqI8Samples, IqI16Samples, SampleError, iq_i8_samples, iq_i16_samples,
};
pub use sequence::{SequenceKey, SequenceStatus, SequenceTracker};
pub use version::{DifiVersionCode, VersionContextPacket};

/// Parses exactly one DIFI packet from a UDP payload.
///
/// This is an alias for [`parse_packet_exact`].
pub fn parse_packet(input: &[u8]) -> Result<Packet<'_>> {
    parse_packet_exact(input)
}

/// Parses exactly one DIFI packet and rejects trailing bytes.
pub fn parse_packet_exact(input: &[u8]) -> Result<Packet<'_>> {
    parser::parse_packet_exact(input)
}

/// Parses the first DIFI packet from the front of `input`.
///
/// The packet size in the DIFI header controls how many bytes are consumed. Any bytes after
/// the first packet are returned as the remainder.
pub fn parse_packet_prefix(input: &[u8]) -> Result<(Packet<'_>, &[u8])> {
    parser::parse_packet_prefix(input)
}
