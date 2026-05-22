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
mod packet_stream;
mod parser;
mod payload_format;
mod raw;
mod samples;
mod sequence;
mod standard;
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
pub use packet_stream::{PacketStreamParser, ParsedDatagram};
pub use payload_format::{PayloadFormat, PayloadSampleFormat};
pub use samples::{
    ComplexI8, ComplexI16, IqI8Samples, IqI16Samples, SampleError, iq_i8_samples, iq_i16_samples,
};
pub use sequence::{SequenceKey, SequenceStatus, SequenceTracker};
pub use standard::{CompatibilityMode, DifiStandardVersion, ParseOptions};
pub use version::{DifiVersionCode, VersionContextPacket};

/// Parses exactly one DIFI packet from a UDP payload.
///
/// This is an alias for [`parse_packet_exact`].
pub fn parse_packet(input: &[u8]) -> Result<Packet<'_>> {
    parse_packet_exact(input)
}

/// Parses exactly one DIFI packet and rejects trailing bytes.
///
/// Defaults to DIFI 1.3.0 strict parsing. Use [`parse_packet_exact_with_options`] to select
/// an older standard profile or compatibility mode.
pub fn parse_packet_exact(input: &[u8]) -> Result<Packet<'_>> {
    parse_packet_exact_with_options(input, ParseOptions::default())
}

/// Parses exactly one DIFI packet with an explicit standard profile and rejects trailing bytes.
pub fn parse_packet_exact_with_options(input: &[u8], options: ParseOptions) -> Result<Packet<'_>> {
    parser::parse_packet_exact_with_options(input, options)
}

/// Parses the first DIFI packet from the front of `input`.
///
/// The packet size in the DIFI header controls how many bytes are consumed. Any bytes after
/// the first packet are returned as the remainder.
///
/// Defaults to DIFI 1.3.0 strict parsing. Use [`parse_packet_prefix_with_options`] to select
/// an older standard profile or compatibility mode.
pub fn parse_packet_prefix(input: &[u8]) -> Result<(Packet<'_>, &[u8])> {
    parse_packet_prefix_with_options(input, ParseOptions::default())
}

/// Parses the first DIFI packet from the front of `input` with an explicit standard profile.
pub fn parse_packet_prefix_with_options(
    input: &[u8],
    options: ParseOptions,
) -> Result<(Packet<'_>, &[u8])> {
    parser::parse_packet_prefix_with_options(input, options)
}
