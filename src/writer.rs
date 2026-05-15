use thiserror::Error;

use crate::command::{
    CapabilityForm, CommandCommon, SinkCapabilitiesQueryPacket, SinkCapabilitiesResponsePacket,
    StatusReportPacket, TimingFlowControlPacket,
};
use crate::context::SignalContextPacket;
use crate::error::ParseError;
use crate::packet::{Packet, Prologue};
use crate::raw::{
    PROLOGUE_BYTES, PROLOGUE_WORDS, WORD_BYTES, write_i64_be, write_u32_be, write_u64_be,
};
use crate::standard::{
    CIF_CONTEXT_CHANGED, CIF_CONTEXT_UNCHANGED, CIF_VERSION_CHANGED, CIF_VERSION_UNCHANGED,
    PacketLayout, ParseOptions, StandardProfile,
};
use crate::validation::validate_fixed_integer_hz;
use crate::{
    ClassId, CompatibilityMode, ComplexI8, ComplexI16, DIFI_CID, DifiStandardVersion,
    DifiVersionCode, InformationClassCode, PacketClassCode, PacketHeader, PacketType,
    PayloadFormat, PayloadSampleFormat, TimestampMode, Tsf, Tsi,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WriteOptions {
    pub standard: DifiStandardVersion,
    pub compatibility: CompatibilityMode,
}

impl WriteOptions {
    pub const DEFAULT: Self = Self {
        standard: DifiStandardVersion::V1_3_0,
        compatibility: CompatibilityMode::Strict,
    };
}

impl Default for WriteOptions {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignalDataWriteSpec {
    pub stream_id: u32,
    pub information_class: InformationClassCode,
    pub packet_class: PacketClassCode,
    pub tsi: Tsi,
    pub tsf: Tsf,
    pub sequence: u8,
    pub integer_seconds_timestamp: u32,
    pub fractional_seconds_timestamp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum WriteError {
    #[error("output buffer too small: need {needed} bytes, got {actual}")]
    OutputTooSmall { needed: usize, actual: usize },

    #[error("packet is too large to encode: {words} words")]
    PacketTooLarge { words: usize },

    #[error("signal data payload length {len} is not word aligned")]
    PayloadLengthNotWordAligned { len: usize },

    #[error("capability table length {len} is not word aligned")]
    CapabilityTableLengthNotWordAligned { len: usize },

    #[error("ComplexI8 IQ data requires an even sample count, got {samples}")]
    OddComplexI8SampleCount { samples: usize },

    #[error("{field} decoded value is out of range: maximum {max}, got {actual}")]
    FieldOutOfRange {
        field: &'static str,
        max: u64,
        actual: u64,
    },

    #[error("{field} is required for this packet form")]
    MissingField { field: &'static str },

    #[error("{field} is not valid for this packet form")]
    UnexpectedField { field: &'static str },

    #[error("{field} raw and decoded values disagree: expected 0x{expected:X}, got 0x{actual:X}")]
    FieldMismatch {
        field: &'static str,
        expected: u64,
        actual: u64,
    },

    #[error("profile validation failed: {source}")]
    Profile { source: ParseError },
}

impl From<ParseError> for WriteError {
    fn from(source: ParseError) -> Self {
        Self::Profile { source }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WritePlan {
    packet_type: PacketType,
    type_specific_bits: u8,
    packet_size_words: u16,
}

pub fn encoded_len(packet: &Packet<'_>) -> Result<usize, WriteError> {
    encoded_len_with_options(packet, WriteOptions::default())
}

pub fn encoded_len_with_options(
    packet: &Packet<'_>,
    options: WriteOptions,
) -> Result<usize, WriteError> {
    let plan = prepare_packet(packet, options)?;
    Ok(plan.packet_size_words as usize * WORD_BYTES)
}

pub fn write_packet(packet: &Packet<'_>, out: &mut [u8]) -> Result<usize, WriteError> {
    write_packet_with_options(packet, out, WriteOptions::default())
}

pub fn write_packet_with_options(
    packet: &Packet<'_>,
    out: &mut [u8],
    options: WriteOptions,
) -> Result<usize, WriteError> {
    let plan = prepare_packet(packet, options)?;
    let encoded_len = plan.packet_size_words as usize * WORD_BYTES;
    if out.len() < encoded_len {
        return Err(WriteError::OutputTooSmall {
            needed: encoded_len,
            actual: out.len(),
        });
    }

    write_prologue(packet.prologue(), plan, &mut out[..encoded_len]);
    match packet {
        Packet::SignalData(packet) => {
            out[PROLOGUE_BYTES..encoded_len].copy_from_slice(packet.payload);
        }
        Packet::SignalContext(packet) => write_signal_context(packet, out),
        Packet::VersionContext(packet) => write_version_context(packet, out),
        Packet::TimingFlowControl(packet) => write_timing_flow_control(packet, out),
        Packet::SinkCapabilitiesQuery(packet) => write_sink_capabilities_query(packet, out)?,
        Packet::SinkCapabilitiesResponse(packet) => write_sink_capabilities_response(packet, out)?,
        Packet::StatusReport(packet) => write_status_report(packet, out)?,
    }

    Ok(encoded_len)
}

pub fn encoded_iq_data_i8_len(
    spec: SignalDataWriteSpec,
    samples: &[ComplexI8],
) -> Result<usize, WriteError> {
    iq_i8_words(spec, samples).map(|words| words as usize * WORD_BYTES)
}

pub fn encoded_iq_data_i16_len(
    spec: SignalDataWriteSpec,
    samples: &[ComplexI16],
) -> Result<usize, WriteError> {
    iq_i16_words(spec, samples).map(|words| words as usize * WORD_BYTES)
}

pub fn write_iq_data_i8(
    spec: SignalDataWriteSpec,
    samples: &[ComplexI8],
    out: &mut [u8],
) -> Result<usize, WriteError> {
    let words = iq_i8_words(spec, samples)?;
    let encoded_len = words as usize * WORD_BYTES;
    if out.len() < encoded_len {
        return Err(WriteError::OutputTooSmall {
            needed: encoded_len,
            actual: out.len(),
        });
    }

    write_signal_data_spec_prologue(spec, words, out);
    let mut offset = PROLOGUE_BYTES;
    for sample in samples {
        out[offset] = sample.i as u8;
        out[offset + 1] = sample.q as u8;
        offset += 2;
    }
    Ok(encoded_len)
}

pub fn write_iq_data_i16(
    spec: SignalDataWriteSpec,
    samples: &[ComplexI16],
    out: &mut [u8],
) -> Result<usize, WriteError> {
    let words = iq_i16_words(spec, samples)?;
    let encoded_len = words as usize * WORD_BYTES;
    if out.len() < encoded_len {
        return Err(WriteError::OutputTooSmall {
            needed: encoded_len,
            actual: out.len(),
        });
    }

    write_signal_data_spec_prologue(spec, words, out);
    let mut offset = PROLOGUE_BYTES;
    for sample in samples {
        out[offset..offset + 2].copy_from_slice(&sample.i.to_be_bytes());
        out[offset + 2..offset + 4].copy_from_slice(&sample.q.to_be_bytes());
        offset += 4;
    }
    Ok(encoded_len)
}

fn prepare_packet(packet: &Packet<'_>, options: WriteOptions) -> Result<WritePlan, WriteError> {
    let packet_size_words = packet_size_words(packet)?;
    let packet_type = packet.prologue().header.packet_type;
    let type_specific_bits = canonical_type_specific_bits(packet)?;
    let plan = WritePlan {
        packet_type,
        type_specific_bits,
        packet_size_words,
    };

    validate_prologue(packet.prologue(), plan, options)?;
    match packet {
        Packet::SignalData(packet) => {
            validate_signal_data(packet.prologue, packet.payload, options)
        }
        Packet::SignalContext(packet) => validate_signal_context(packet, options),
        Packet::VersionContext(packet) => validate_version_context(packet, options),
        Packet::TimingFlowControl(packet) => validate_timing_flow_control(packet, options),
        Packet::SinkCapabilitiesQuery(packet) => validate_sink_capabilities_query(packet, options),
        Packet::SinkCapabilitiesResponse(packet) => {
            validate_sink_capabilities_response(packet, options)
        }
        Packet::StatusReport(packet) => validate_status_report(packet, options),
    }?;

    Ok(plan)
}

fn packet_size_words(packet: &Packet<'_>) -> Result<u16, WriteError> {
    let words = match packet {
        Packet::SignalData(packet) => {
            if !packet.payload.len().is_multiple_of(WORD_BYTES) {
                return Err(WriteError::PayloadLengthNotWordAligned {
                    len: packet.payload.len(),
                });
            }
            PROLOGUE_WORDS as usize + packet.payload.len() / WORD_BYTES
        }
        Packet::SignalContext(_) => 27,
        Packet::VersionContext(_) => 11,
        Packet::TimingFlowControl(_) => 21,
        Packet::SinkCapabilitiesQuery(packet) => match packet.form {
            CapabilityForm::Long => 13,
            CapabilityForm::Short => 15,
        },
        Packet::SinkCapabilitiesResponse(packet) => match packet.form {
            CapabilityForm::Short => 18,
            CapabilityForm::Long => {
                if !packet.capability_table.len().is_multiple_of(WORD_BYTES) {
                    return Err(WriteError::CapabilityTableLengthNotWordAligned {
                        len: packet.capability_table.len(),
                    });
                }
                13 + packet.capability_table.len() / WORD_BYTES
            }
        },
        Packet::StatusReport(packet) => status_report_words(packet)?,
    };

    u16::try_from(words).map_err(|_| WriteError::PacketTooLarge { words })
}

fn status_report_words(packet: &StatusReportPacket) -> Result<usize, WriteError> {
    match (
        packet.reference_level_limit,
        packet.sample_rate_limit,
        packet.bandwidth_limit,
    ) {
        (None, None, None) => Ok(15),
        (Some(_), None, None) => Ok(17),
        (Some(_), Some(_), Some(_)) => Ok(21),
        (None, Some(_), _) | (None, _, Some(_)) => Err(WriteError::MissingField {
            field: "reference_level_limit",
        }),
        (Some(_), Some(_), None) => Err(WriteError::MissingField {
            field: "bandwidth_limit",
        }),
        (Some(_), None, Some(_)) => Err(WriteError::MissingField {
            field: "sample_rate_limit",
        }),
    }
}

fn canonical_type_specific_bits(packet: &Packet<'_>) -> Result<u8, WriteError> {
    match packet {
        Packet::SignalData(_) | Packet::TimingFlowControl(_) => Ok(0),
        Packet::SignalContext(packet) => tsm_type_specific(packet.prologue.header.tsm),
        Packet::VersionContext(packet) => tsm_type_specific(packet.prologue.header.tsm),
        Packet::SinkCapabilitiesQuery(_) | Packet::StatusReport(_) => Ok(0),
        Packet::SinkCapabilitiesResponse(_) => Ok(0b100),
    }
}

fn tsm_type_specific(tsm: Option<TimestampMode>) -> Result<u8, WriteError> {
    match tsm {
        Some(TimestampMode::Fine) => Ok(0),
        Some(TimestampMode::Coarse) => Ok(1),
        None => Err(WriteError::MissingField {
            field: "header.tsm",
        }),
    }
}

fn validate_prologue(
    prologue: &Prologue,
    plan: WritePlan,
    options: WriteOptions,
) -> Result<(), WriteError> {
    if prologue.header.sequence > 0x0F {
        return Err(WriteError::FieldOutOfRange {
            field: "header.sequence",
            max: 0x0F,
            actual: prologue.header.sequence as u64,
        });
    }
    if prologue.header.packet_type != plan.packet_type {
        return Err(WriteError::FieldMismatch {
            field: "header.packet_type",
            expected: plan.packet_type as u64,
            actual: prologue.header.packet_type as u64,
        });
    }
    if prologue.header.type_specific_bits != plan.type_specific_bits {
        return Err(WriteError::FieldMismatch {
            field: "header.type_specific_bits",
            expected: plan.type_specific_bits as u64,
            actual: prologue.header.type_specific_bits as u64,
        });
    }
    if !prologue.header.class_id_indicator {
        return Err(WriteError::FieldMismatch {
            field: "header.class_id_indicator",
            expected: 1,
            actual: 0,
        });
    }
    if prologue.header.packet_size_words != plan.packet_size_words {
        return Err(WriteError::FieldMismatch {
            field: "header.packet_size_words",
            expected: plan.packet_size_words as u64,
            actual: prologue.header.packet_size_words as u64,
        });
    }
    let expected_tsm = match plan.packet_type {
        PacketType::ContextWithStreamId | PacketType::VersionWithStreamId => {
            if plan.type_specific_bits & 1 == 1 {
                Some(TimestampMode::Coarse)
            } else {
                Some(TimestampMode::Fine)
            }
        }
        _ => None,
    };
    if prologue.header.tsm != expected_tsm {
        return Err(WriteError::FieldMismatch {
            field: "header.tsm",
            expected: expected_tsm.map_or(2, |tsm| tsm as u64),
            actual: prologue.header.tsm.map_or(2, |tsm| tsm as u64),
        });
    }

    validate_class_id(prologue.class_id)?;

    let header_word = header_word(
        plan.packet_type,
        plan.type_specific_bits,
        prologue.header.tsi,
        prologue.header.tsf,
        prologue.header.sequence,
        plan.packet_size_words,
    )?;
    if prologue.header.raw != header_word {
        return Err(WriteError::FieldMismatch {
            field: "header.raw",
            expected: header_word as u64,
            actual: prologue.header.raw as u64,
        });
    }

    let profile = profile(options);
    let header = PacketHeader {
        raw: header_word,
        packet_type: plan.packet_type,
        class_id_indicator: true,
        type_specific_bits: plan.type_specific_bits,
        tsm: expected_tsm,
        tsi: prologue.header.tsi,
        tsf: prologue.header.tsf,
        sequence: prologue.header.sequence,
        packet_size_words: plan.packet_size_words,
    };
    profile.validate_packet_type_available(plan.packet_type)?;
    profile.validate_packet_class_available(prologue.class_id.packet_class)?;
    profile.validate_packet_type_class(plan.packet_type, prologue.class_id.packet_class)?;
    profile.validate_header_bits(header, prologue.class_id.packet_class)?;
    profile.validate_class_membership(
        prologue.class_id.information_class,
        prologue.class_id.packet_class,
    )?;
    profile.validate_tsf(header, prologue.class_id.packet_class)?;
    profile.validate_tsm(
        header,
        prologue.class_id.information_class,
        prologue.class_id.packet_class,
    )?;

    Ok(())
}

fn validate_class_id(class_id: ClassId) -> Result<(), WriteError> {
    if class_id.pad_bit_count > 0x1F {
        return Err(WriteError::FieldOutOfRange {
            field: "class_id.pad_bit_count",
            max: 0x1F,
            actual: class_id.pad_bit_count as u64,
        });
    }
    if class_id.oui != DIFI_CID {
        return Err(WriteError::FieldMismatch {
            field: "class_id.oui",
            expected: DIFI_CID as u64,
            actual: class_id.oui as u64,
        });
    }
    Ok(())
}

fn validate_signal_data(
    prologue: Prologue,
    payload: &[u8],
    options: WriteOptions,
) -> Result<(), WriteError> {
    if !payload.len().is_multiple_of(WORD_BYTES) {
        return Err(WriteError::PayloadLengthNotWordAligned { len: payload.len() });
    }
    let profile = profile(options);
    let information_class = prologue.class_id.information_class;
    let packet_class = prologue.class_id.packet_class;
    let pad_bit_count = prologue.class_id.pad_bit_count;
    if pad_bit_count != 0 && !profile.permits_data_padding(information_class, packet_class) {
        return Err(ParseError::PadBitsNotAllowed {
            information_class,
            packet_class,
            pad_bit_count,
        }
        .into());
    }
    validate_data_padding(payload, pad_bit_count)?;
    Ok(())
}

fn validate_signal_context(
    packet: &SignalContextPacket,
    options: WriteOptions,
) -> Result<(), WriteError> {
    expect_no_padding(packet.prologue)?;
    let profile = profile(options);
    profile.expect_packet_size(
        PacketLayout::SignalContext,
        packet.prologue.class_id.packet_class,
        packet.prologue.header.packet_size_words,
    )?;
    profile.expect_signal_context_cif0(packet.cif0)?;
    let expected_cif0 = if packet.context_changed {
        CIF_CONTEXT_CHANGED
    } else {
        CIF_CONTEXT_UNCHANGED
    };
    expect_field(
        "signal_context.cif0",
        expected_cif0 as u64,
        packet.cif0 as u64,
    )?;
    validate_fixed_integer_hz("context bandwidth", packet.bandwidth.0)?;
    validate_fixed_integer_hz(
        "context IF reference frequency",
        packet.if_reference_frequency.0 as u64,
    )?;
    validate_fixed_integer_hz(
        "context RF reference frequency",
        packet.rf_reference_frequency.0 as u64,
    )?;
    validate_fixed_integer_hz("context IF band offset", packet.if_band_offset.0 as u64)?;
    validate_fixed_integer_hz("context sample rate", packet.sample_rate.0)?;
    validate_payload_format(packet.payload_format)?;
    Ok(())
}

fn validate_version_context(
    packet: &crate::VersionContextPacket,
    options: WriteOptions,
) -> Result<(), WriteError> {
    expect_no_padding(packet.prologue)?;
    let profile = profile(options);
    profile.expect_packet_size(
        PacketLayout::VersionContext,
        packet.prologue.class_id.packet_class,
        packet.prologue.header.packet_size_words,
    )?;
    profile.expect_version_context_cif0(packet.cif0)?;
    let expected_cif0 = if packet.context_changed {
        CIF_VERSION_CHANGED
    } else {
        CIF_VERSION_UNCHANGED
    };
    expect_field(
        "version_context.cif0",
        expected_cif0 as u64,
        packet.cif0 as u64,
    )?;
    profile.expect_version_context_cif1(packet.cif1)?;
    profile.expect_vita49_spec_version(packet.vita49_spec_version)?;
    if packet.year > 0x7F {
        return Err(WriteError::FieldOutOfRange {
            field: "version_context.year",
            max: 0x7F,
            actual: packet.year as u64,
        });
    }
    if packet.day > 0x01FF {
        return Err(WriteError::FieldOutOfRange {
            field: "version_context.day",
            max: 0x01FF,
            actual: packet.day as u64,
        });
    }
    if packet.revision > 0x3F {
        return Err(WriteError::FieldOutOfRange {
            field: "version_context.revision",
            max: 0x3F,
            actual: packet.revision as u64,
        });
    }
    expect_field("version_context.device_type", 0, packet.device_type as u64)?;
    expect_field(
        "version_context.icd_version",
        DifiVersionCode::Version1 as u64,
        packet.icd_version as u64,
    )?;
    Ok(())
}

fn validate_timing_flow_control(
    packet: &TimingFlowControlPacket,
    options: WriteOptions,
) -> Result<(), WriteError> {
    expect_no_padding(packet.prologue)?;
    let profile = profile(options);
    profile.expect_packet_size(
        PacketLayout::TimingFlowControl,
        packet.prologue.class_id.packet_class,
        packet.prologue.header.packet_size_words,
    )?;
    profile.expect_timing_flow_control_cam(packet.common.cam)?;
    profile.expect_timing_flow_control_cif0(packet.cif0)?;
    profile.expect_timing_flow_control_cif1(packet.cif1)?;
    validate_fixed_integer_hz("timing flow control sample rate", packet.sample_rate.0)?;
    validate_buffer_status(packet.buffer_status)?;
    Ok(())
}

fn validate_sink_capabilities_query(
    packet: &SinkCapabilitiesQueryPacket,
    options: WriteOptions,
) -> Result<(), WriteError> {
    expect_no_padding(packet.prologue)?;
    let profile = profile(options);
    profile.expect_sink_capabilities_query_cam(packet.common.cam)?;
    match packet.form {
        CapabilityForm::Long => {
            profile.expect_packet_size(
                PacketLayout::SinkCapabilitiesQueryLong,
                packet.prologue.class_id.packet_class,
                packet.prologue.header.packet_size_words,
            )?;
            profile.expect_sink_capabilities_long_query_cif0(packet.cif0)?;
            let cif1 = packet
                .cif1
                .ok_or(WriteError::MissingField { field: "cif1" })?;
            profile.expect_sink_capabilities_long_query_cif1(cif1)?;
            expect_absent_u32(
                "sink_time_calibration_integer",
                packet.sink_time_calibration_integer,
            )?;
            expect_absent_u64(
                "sink_time_calibration_fractional",
                packet.sink_time_calibration_fractional,
            )?;
        }
        CapabilityForm::Short => {
            profile.expect_packet_size(
                PacketLayout::SinkCapabilitiesQueryShort,
                packet.prologue.class_id.packet_class,
                packet.prologue.header.packet_size_words,
            )?;
            profile.expect_sink_capabilities_short_query_cif0(packet.cif0)?;
            expect_absent_u32("cif1", packet.cif1)?;
            let _ = packet
                .sink_time_calibration_integer
                .ok_or(WriteError::MissingField {
                    field: "sink_time_calibration_integer",
                })?;
            let _ = packet
                .sink_time_calibration_fractional
                .ok_or(WriteError::MissingField {
                    field: "sink_time_calibration_fractional",
                })?;
        }
    }
    Ok(())
}

fn validate_sink_capabilities_response(
    packet: &SinkCapabilitiesResponsePacket<'_>,
    options: WriteOptions,
) -> Result<(), WriteError> {
    expect_no_padding(packet.prologue)?;
    let profile = profile(options);
    profile.expect_sink_capabilities_response_cam(packet.common.cam)?;
    match packet.form {
        CapabilityForm::Long => {
            if !packet.capability_table.len().is_multiple_of(WORD_BYTES) {
                return Err(WriteError::CapabilityTableLengthNotWordAligned {
                    len: packet.capability_table.len(),
                });
            }
            if packet.prologue.header.packet_size_words <= 13 {
                return Err(ParseError::InvalidPacketSize {
                    packet_class: packet.prologue.class_id.packet_class,
                    expected: 14,
                    actual: packet.prologue.header.packet_size_words,
                }
                .into());
            }
            profile.expect_sink_capabilities_long_response_cif0(packet.cif0)?;
            let cif1 = packet
                .cif1
                .ok_or(WriteError::MissingField { field: "cif1" })?;
            profile.expect_sink_capabilities_long_response_cif1(cif1)?;
            expect_absent_u32(
                "control_packet_integer_timestamp",
                packet.control_packet_integer_timestamp,
            )?;
            expect_absent_u64(
                "control_packet_fractional_timestamp",
                packet.control_packet_fractional_timestamp,
            )?;
            expect_absent_u32(
                "sink_reception_integer_timestamp",
                packet.sink_reception_integer_timestamp,
            )?;
            expect_absent_u64(
                "sink_reception_fractional_timestamp",
                packet.sink_reception_fractional_timestamp,
            )?;
        }
        CapabilityForm::Short => {
            profile.expect_packet_size(
                PacketLayout::SinkCapabilitiesResponseShort,
                packet.prologue.class_id.packet_class,
                packet.prologue.header.packet_size_words,
            )?;
            profile.expect_sink_capabilities_short_response_cif0(packet.cif0)?;
            expect_absent_u32("cif1", packet.cif1)?;
            if !packet.capability_table.is_empty() {
                return Err(WriteError::UnexpectedField {
                    field: "capability_table",
                });
            }
            let _ = packet
                .control_packet_integer_timestamp
                .ok_or(WriteError::MissingField {
                    field: "control_packet_integer_timestamp",
                })?;
            let _ = packet
                .control_packet_fractional_timestamp
                .ok_or(WriteError::MissingField {
                    field: "control_packet_fractional_timestamp",
                })?;
            let _ = packet
                .sink_reception_integer_timestamp
                .ok_or(WriteError::MissingField {
                    field: "sink_reception_integer_timestamp",
                })?;
            let _ = packet
                .sink_reception_fractional_timestamp
                .ok_or(WriteError::MissingField {
                    field: "sink_reception_fractional_timestamp",
                })?;
        }
    }
    Ok(())
}

fn validate_status_report(
    packet: &StatusReportPacket,
    options: WriteOptions,
) -> Result<(), WriteError> {
    expect_no_padding(packet.prologue)?;
    let profile = profile(options);
    profile.validate_status_report_size(
        packet.prologue.class_id.packet_class,
        packet.prologue.header.packet_size_words,
    )?;
    profile.expect_status_report_cam(packet.common.cam)?;
    profile.expect_status_report_cif0(packet.cif0)?;
    profile.expect_status_report_cif1(packet.cif1)?;

    let expected_flags = match status_report_words(packet)? {
        15 => 0,
        17 => 0x10,
        21 => 0x18,
        _ => unreachable!("status report packet size is constrained above"),
    };
    expect_field(
        "status_report.quantitative_flags",
        expected_flags,
        (packet.sink_errors_warnings & 0x18) as u64,
    )?;
    if let Some(sample_rate) = packet.sample_rate_limit {
        validate_fixed_integer_hz("status sample rate limit", sample_rate.0)?;
    }
    if let Some(bandwidth) = packet.bandwidth_limit {
        validate_fixed_integer_hz("status bandwidth limit", bandwidth.0)?;
    }
    Ok(())
}

fn validate_payload_format(payload_format: PayloadFormat) -> Result<(), WriteError> {
    if payload_format.sample_format != PayloadSampleFormat::ComplexSignedCartesian {
        return Err(WriteError::FieldMismatch {
            field: "payload_format.sample_format",
            expected: 0,
            actual: 1,
        });
    }
    if !(4..=16).contains(&payload_format.data_item_size_bits) {
        return Err(WriteError::FieldOutOfRange {
            field: "payload_format.data_item_size_bits",
            max: 16,
            actual: payload_format.data_item_size_bits as u64,
        });
    }
    if payload_format.item_packing_field_size_bits != payload_format.data_item_size_bits {
        return Err(WriteError::FieldMismatch {
            field: "payload_format.item_packing_field_size_bits",
            expected: payload_format.data_item_size_bits as u64,
            actual: payload_format.item_packing_field_size_bits as u64,
        });
    }
    let minus_one = (payload_format.data_item_size_bits - 1) as u32;
    let expected_word0 = 0xA000_0000 | (minus_one << 6) | minus_one;
    expect_field(
        "payload_format.raw_word0",
        expected_word0 as u64,
        payload_format.raw_word0 as u64,
    )?;
    expect_field(
        "payload_format.raw_word1",
        0,
        payload_format.raw_word1 as u64,
    )?;
    Ok(())
}

fn validate_buffer_status(status: crate::BufferStatus) -> Result<(), WriteError> {
    if status.buffer_level > 0x0FFF {
        return Err(WriteError::FieldOutOfRange {
            field: "buffer_status.buffer_level",
            max: 0x0FFF,
            actual: status.buffer_level as u64,
        });
    }
    let flags = ((status.overflow as u32) << 3)
        | ((status.nearly_full as u32) << 2)
        | ((status.nearly_empty as u32) << 1)
        | status.underflow as u32;
    let expected = ((status.buffer_level as u32) << 4) | flags;
    expect_field("buffer_status.raw", expected as u64, status.raw as u64)
}

fn expect_no_padding(prologue: Prologue) -> Result<(), WriteError> {
    if prologue.class_id.pad_bit_count == 0 {
        Ok(())
    } else {
        Err(ParseError::PadBitsNotAllowed {
            information_class: prologue.class_id.information_class,
            packet_class: prologue.class_id.packet_class,
            pad_bit_count: prologue.class_id.pad_bit_count,
        }
        .into())
    }
}

fn validate_data_padding(payload: &[u8], pad_bit_count: u8) -> Result<(), WriteError> {
    if pad_bit_count == 0 {
        return Ok(());
    }
    let payload_bits = payload.len() * 8;
    if pad_bit_count as usize > payload_bits || payload.is_empty() {
        return Err(ParseError::InvalidPadding {
            pad_bit_count,
            payload_bits,
        }
        .into());
    }

    let full_pad_bytes = (pad_bit_count / 8) as usize;
    let partial_pad_bits = pad_bit_count % 8;

    if full_pad_bytes != 0 {
        let start = payload.len() - full_pad_bytes;
        if payload[start..].iter().any(|byte| *byte != 0) {
            return Err(ParseError::NonZeroPaddingBits.into());
        }
    }

    if partial_pad_bits != 0 {
        let byte_index = payload.len() - full_pad_bytes - 1;
        let mask = (1u16 << partial_pad_bits) - 1;
        if (payload[byte_index] as u16) & mask != 0 {
            return Err(ParseError::NonZeroPaddingBits.into());
        }
    }

    Ok(())
}

fn write_prologue(prologue: &Prologue, plan: WritePlan, out: &mut [u8]) {
    let header_word = header_word(
        plan.packet_type,
        plan.type_specific_bits,
        prologue.header.tsi,
        prologue.header.tsf,
        prologue.header.sequence,
        plan.packet_size_words,
    )
    .expect("validated header fields before writing");
    write_u32_be(out, 0, header_word);
    write_u32_be(out, 1, prologue.stream_id);
    write_u32_be(
        out,
        2,
        ((prologue.class_id.pad_bit_count as u32) << 27) | prologue.class_id.oui,
    );
    write_u32_be(
        out,
        3,
        ((prologue.class_id.information_class.raw() as u32) << 16)
            | prologue.class_id.packet_class.raw() as u32,
    );
    write_u32_be(out, 4, prologue.integer_seconds_timestamp);
    write_u64_be(out, 5, prologue.fractional_seconds_timestamp);
}

fn write_signal_context(packet: &SignalContextPacket, out: &mut [u8]) {
    write_u32_be(out, 7, packet.cif0);
    write_u32_be(out, 8, packet.reference_point);
    write_u64_be(out, 9, packet.bandwidth.0);
    write_i64_be(out, 11, packet.if_reference_frequency.0);
    write_i64_be(out, 13, packet.rf_reference_frequency.0);
    write_i64_be(out, 15, packet.if_band_offset.0);
    write_u32_be(
        out,
        17,
        ((packet.scaling_level as u16 as u32) << 16) | packet.reference_level as u16 as u32,
    );
    write_u32_be(out, 18, ((packet.gain2 as u32) << 16) | packet.gain1 as u32);
    write_u64_be(out, 19, packet.sample_rate.0);
    write_i64_be(out, 21, packet.timestamp_adjustment.0);
    write_u32_be(out, 23, packet.timestamp_calibration_time);
    write_u32_be(out, 24, packet.state_and_event_indicators);
    write_u32_be(out, 25, packet.payload_format.raw_word0);
    write_u32_be(out, 26, packet.payload_format.raw_word1);
}

fn write_version_context(packet: &crate::VersionContextPacket, out: &mut [u8]) {
    write_u32_be(out, 7, packet.cif0);
    write_u32_be(out, 8, packet.cif1);
    write_u32_be(out, 9, packet.vita49_spec_version);
    let version_word = ((packet.year as u32) << 25)
        | ((packet.day as u32) << 16)
        | ((packet.revision as u32) << 10)
        | ((packet.device_type as u32) << 6)
        | packet.icd_version as u32;
    write_u32_be(out, 10, version_word);
}

fn write_timing_flow_control(packet: &TimingFlowControlPacket, out: &mut [u8]) {
    write_common(packet.common, out);
    write_u32_be(out, 11, packet.cif0);
    write_u32_be(out, 12, packet.cif1);
    write_u32_be(out, 13, packet.reference_point);
    write_u64_be(out, 14, packet.sample_rate.0);
    write_i64_be(out, 16, packet.timestamp_adjustment.0);
    write_u64_be(out, 18, packet.buffer_size_bytes);
    write_u32_be(out, 20, packet.buffer_status.raw);
}

fn write_sink_capabilities_query(
    packet: &SinkCapabilitiesQueryPacket,
    out: &mut [u8],
) -> Result<(), WriteError> {
    write_common(packet.common, out);
    write_u32_be(out, 11, packet.cif0);
    match packet.form {
        CapabilityForm::Long => {
            write_u32_be(
                out,
                12,
                packet
                    .cif1
                    .ok_or(WriteError::MissingField { field: "cif1" })?,
            );
        }
        CapabilityForm::Short => {
            write_u32_be(
                out,
                12,
                packet
                    .sink_time_calibration_integer
                    .ok_or(WriteError::MissingField {
                        field: "sink_time_calibration_integer",
                    })?,
            );
            write_u64_be(
                out,
                13,
                packet
                    .sink_time_calibration_fractional
                    .ok_or(WriteError::MissingField {
                        field: "sink_time_calibration_fractional",
                    })?,
            );
        }
    }
    Ok(())
}

fn write_sink_capabilities_response(
    packet: &SinkCapabilitiesResponsePacket<'_>,
    out: &mut [u8],
) -> Result<(), WriteError> {
    write_common(packet.common, out);
    write_u32_be(out, 11, packet.cif0);
    match packet.form {
        CapabilityForm::Long => {
            write_u32_be(
                out,
                12,
                packet
                    .cif1
                    .ok_or(WriteError::MissingField { field: "cif1" })?,
            );
            out[13 * WORD_BYTES..13 * WORD_BYTES + packet.capability_table.len()]
                .copy_from_slice(packet.capability_table);
        }
        CapabilityForm::Short => {
            write_u32_be(
                out,
                12,
                packet
                    .control_packet_integer_timestamp
                    .ok_or(WriteError::MissingField {
                        field: "control_packet_integer_timestamp",
                    })?,
            );
            write_u64_be(
                out,
                13,
                packet
                    .control_packet_fractional_timestamp
                    .ok_or(WriteError::MissingField {
                        field: "control_packet_fractional_timestamp",
                    })?,
            );
            write_u32_be(
                out,
                15,
                packet
                    .sink_reception_integer_timestamp
                    .ok_or(WriteError::MissingField {
                        field: "sink_reception_integer_timestamp",
                    })?,
            );
            write_u64_be(
                out,
                16,
                packet
                    .sink_reception_fractional_timestamp
                    .ok_or(WriteError::MissingField {
                        field: "sink_reception_fractional_timestamp",
                    })?,
            );
        }
    }
    Ok(())
}

fn write_status_report(packet: &StatusReportPacket, out: &mut [u8]) -> Result<(), WriteError> {
    write_common(packet.common, out);
    write_u32_be(out, 11, packet.cif0);
    write_u32_be(out, 12, packet.cif1);
    write_u32_be(out, 13, packet.packet_errors);
    write_u32_be(out, 14, packet.sink_errors_warnings);
    if let Some(reference_level_limit) = packet.reference_level_limit {
        write_u32_be(out, 15, reference_level_limit.raw_min_max);
        write_u32_be(out, 16, reference_level_limit.raw_resolution_reserved);
    }
    if let Some(sample_rate_limit) = packet.sample_rate_limit {
        write_u64_be(out, 17, sample_rate_limit.0);
    }
    if let Some(bandwidth_limit) = packet.bandwidth_limit {
        write_u64_be(out, 19, bandwidth_limit.0);
    }
    Ok(())
}

fn write_common(common: CommandCommon, out: &mut [u8]) {
    write_u32_be(out, 7, common.cam);
    write_u32_be(out, 8, common.message_id);
    write_u32_be(out, 9, common.controllee_id);
    write_u32_be(out, 10, common.controller_id);
}

fn iq_i8_words(spec: SignalDataWriteSpec, samples: &[ComplexI8]) -> Result<u16, WriteError> {
    if !samples.len().is_multiple_of(2) {
        return Err(WriteError::OddComplexI8SampleCount {
            samples: samples.len(),
        });
    }
    let payload_bytes = samples
        .len()
        .checked_mul(2)
        .ok_or(WriteError::PacketTooLarge { words: usize::MAX })?;
    signal_data_spec_words(spec, payload_bytes)
}

fn iq_i16_words(spec: SignalDataWriteSpec, samples: &[ComplexI16]) -> Result<u16, WriteError> {
    let payload_bytes = samples
        .len()
        .checked_mul(4)
        .ok_or(WriteError::PacketTooLarge { words: usize::MAX })?;
    signal_data_spec_words(spec, payload_bytes)
}

fn signal_data_spec_words(
    spec: SignalDataWriteSpec,
    payload_bytes: usize,
) -> Result<u16, WriteError> {
    if !payload_bytes.is_multiple_of(WORD_BYTES) {
        return Err(WriteError::PayloadLengthNotWordAligned { len: payload_bytes });
    }
    if spec.sequence > 0x0F {
        return Err(WriteError::FieldOutOfRange {
            field: "sequence",
            max: 0x0F,
            actual: spec.sequence as u64,
        });
    }

    let words = PROLOGUE_WORDS as usize + payload_bytes / WORD_BYTES;
    let packet_size_words =
        u16::try_from(words).map_err(|_| WriteError::PacketTooLarge { words })?;
    let header_word = header_word(
        PacketType::SignalDataWithStreamId,
        0,
        spec.tsi,
        spec.tsf,
        spec.sequence,
        packet_size_words,
    )?;
    let class_id = ClassId {
        pad_bit_count: 0,
        oui: DIFI_CID,
        information_class: spec.information_class,
        packet_class: spec.packet_class,
    };
    let profile = profile(WriteOptions::default());
    let header = PacketHeader {
        raw: header_word,
        packet_type: PacketType::SignalDataWithStreamId,
        class_id_indicator: true,
        type_specific_bits: 0,
        tsm: None,
        tsi: spec.tsi,
        tsf: spec.tsf,
        sequence: spec.sequence,
        packet_size_words,
    };
    profile.validate_packet_type_available(PacketType::SignalDataWithStreamId)?;
    profile.validate_packet_class_available(spec.packet_class)?;
    profile.validate_packet_type_class(PacketType::SignalDataWithStreamId, spec.packet_class)?;
    profile.validate_header_bits(header, spec.packet_class)?;
    profile.validate_class_membership(spec.information_class, spec.packet_class)?;
    profile.validate_tsf(header, spec.packet_class)?;
    profile.validate_tsm(header, spec.information_class, spec.packet_class)?;
    validate_class_id(class_id)?;
    Ok(packet_size_words)
}

fn write_signal_data_spec_prologue(spec: SignalDataWriteSpec, words: u16, out: &mut [u8]) {
    let header = header_word(
        PacketType::SignalDataWithStreamId,
        0,
        spec.tsi,
        spec.tsf,
        spec.sequence,
        words,
    )
    .expect("validated header fields before writing");
    write_u32_be(out, 0, header);
    write_u32_be(out, 1, spec.stream_id);
    write_u32_be(out, 2, DIFI_CID);
    write_u32_be(
        out,
        3,
        ((spec.information_class.raw() as u32) << 16) | spec.packet_class.raw() as u32,
    );
    write_u32_be(out, 4, spec.integer_seconds_timestamp);
    write_u64_be(out, 5, spec.fractional_seconds_timestamp);
}

fn header_word(
    packet_type: PacketType,
    type_specific_bits: u8,
    tsi: Tsi,
    tsf: Tsf,
    sequence: u8,
    packet_size_words: u16,
) -> Result<u32, WriteError> {
    if type_specific_bits > 0x7 {
        return Err(WriteError::FieldOutOfRange {
            field: "header.type_specific_bits",
            max: 0x7,
            actual: type_specific_bits as u64,
        });
    }
    if sequence > 0x0F {
        return Err(WriteError::FieldOutOfRange {
            field: "header.sequence",
            max: 0x0F,
            actual: sequence as u64,
        });
    }

    Ok(((packet_type as u32) << 28)
        | (1 << 27)
        | ((type_specific_bits as u32) << 24)
        | ((tsi as u32) << 22)
        | ((tsf as u32) << 20)
        | ((sequence as u32) << 16)
        | packet_size_words as u32)
}

fn profile(options: WriteOptions) -> StandardProfile {
    StandardProfile::new(ParseOptions {
        standard: options.standard,
        compatibility: options.compatibility,
    })
}

fn expect_field(field: &'static str, expected: u64, actual: u64) -> Result<(), WriteError> {
    if expected == actual {
        Ok(())
    } else {
        Err(WriteError::FieldMismatch {
            field,
            expected,
            actual,
        })
    }
}

fn expect_absent_u32(field: &'static str, value: Option<u32>) -> Result<(), WriteError> {
    if value.is_none() {
        Ok(())
    } else {
        Err(WriteError::UnexpectedField { field })
    }
}

fn expect_absent_u64(field: &'static str, value: Option<u64>) -> Result<(), WriteError> {
    if value.is_none() {
        Ok(())
    } else {
        Err(WriteError::UnexpectedField { field })
    }
}
