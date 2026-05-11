use crate::command::{
    BufferStatus, CapabilityForm, CommandCommon, ReferenceLevelLimit, SinkCapabilitiesQueryPacket,
    SinkCapabilitiesResponsePacket, StatusReportPacket, TimingFlowControlPacket,
};
use crate::context::{FixedI64, FixedU64, SignalContextPacket};
use crate::data::SignalDataPacket;
use crate::error::{ParseError, Result};
use crate::packet::{Packet, Prologue};
use crate::raw::{
    PROLOGUE_BYTES, PROLOGUE_WORDS, WORD_BYTES, read_i64_be, read_u32_be, read_u64_be,
};
use crate::standard::{
    CIF_CONTEXT_CHANGED, CIF_VERSION_CHANGED, PacketLayout, ParseOptions, StandardProfile,
};
use crate::validation::validate_fixed_integer_hz;
use crate::{ClassId, DifiVersionCode, PacketClassCode, PacketHeader, PayloadFormat};

pub(crate) fn parse_packet_exact_with_options(
    input: &[u8],
    options: ParseOptions,
) -> Result<Packet<'_>> {
    let (packet, remainder) = parse_packet_prefix_with_options(input, options)?;
    if remainder.is_empty() {
        Ok(packet)
    } else {
        Err(ParseError::TrailingBytes {
            trailing: remainder.len(),
        })
    }
}

pub(crate) fn parse_packet_prefix_with_options(
    input: &[u8],
    options: ParseOptions,
) -> Result<(Packet<'_>, &[u8])> {
    if input.len() < PROLOGUE_BYTES {
        return Err(ParseError::InputTooShort {
            min: PROLOGUE_BYTES,
            actual: input.len(),
        });
    }

    let header_word = read_u32_be(input, 0)?;
    let packet_size_words = (header_word & 0xFFFF) as u16;
    if packet_size_words < PROLOGUE_WORDS {
        return Err(ParseError::PacketSizeTooSmall {
            words: packet_size_words,
        });
    }

    let packet_len = packet_size_words as usize * WORD_BYTES;
    if input.len() < packet_len {
        return Err(ParseError::PacketTruncated {
            needed: packet_len,
            actual: input.len(),
        });
    }

    let packet_bytes = &input[..packet_len];
    let remainder = &input[packet_len..];
    let profile = StandardProfile::new(options);
    let packet = parse_single_packet(packet_bytes, profile)?;
    Ok((packet, remainder))
}

fn parse_single_packet(input: &[u8], profile: StandardProfile) -> Result<Packet<'_>> {
    let header = PacketHeader::parse(read_u32_be(input, 0)?)?;
    if !header.class_id_indicator {
        return Err(ParseError::MissingClassId);
    }
    let class_id = ClassId::parse(read_u32_be(input, 2)?, read_u32_be(input, 3)?)?;
    profile.validate_packet_type_available(header.packet_type)?;
    profile.validate_packet_class_available(class_id.packet_class)?;
    profile.validate_packet_type_class(header.packet_type, class_id.packet_class)?;
    profile.validate_header_bits(header, class_id.packet_class)?;
    profile.validate_class_membership(class_id.information_class, class_id.packet_class)?;
    profile.validate_tsf(header, class_id.packet_class)?;
    profile.validate_tsm(header, class_id.information_class, class_id.packet_class)?;

    let prologue = Prologue {
        header,
        stream_id: read_u32_be(input, 1)?,
        class_id,
        integer_seconds_timestamp: read_u32_be(input, 4)?,
        fractional_seconds_timestamp: read_u64_be(input, 5)?,
    };

    match class_id.packet_class {
        PacketClassCode::StandardFlowSignalData | PacketClassCode::SampleCountSignalData => {
            parse_data(input, prologue, profile).map(Packet::SignalData)
        }
        PacketClassCode::StandardFlowSignalContext | PacketClassCode::SampleCountSignalContext => {
            parse_signal_context(input, prologue, profile).map(Packet::SignalContext)
        }
        PacketClassCode::VersionFlowSignalContext => {
            parse_version_context(input, prologue, profile).map(Packet::VersionContext)
        }
        PacketClassCode::SampleCountTimingFlowControl
        | PacketClassCode::RealTimeTimingFlowControl => {
            parse_timing_flow_control(input, prologue, profile).map(Packet::TimingFlowControl)
        }
        PacketClassCode::SinkCapabilitiesQuery => {
            parse_sink_capabilities_query(input, prologue, profile)
                .map(Packet::SinkCapabilitiesQuery)
        }
        PacketClassCode::SinkCapabilitiesResponse => {
            parse_sink_capabilities_response(input, prologue, profile)
                .map(Packet::SinkCapabilitiesResponse)
        }
        PacketClassCode::StatusReport => {
            parse_status_report(input, prologue, profile).map(Packet::StatusReport)
        }
    }
}

fn parse_data<'a>(
    input: &'a [u8],
    prologue: Prologue,
    profile: StandardProfile,
) -> Result<SignalDataPacket<'a>> {
    let packet_class = prologue.class_id.packet_class;
    let information_class = prologue.class_id.information_class;
    if prologue.header.packet_size_words < PROLOGUE_WORDS {
        return Err(ParseError::PacketSizeTooSmall {
            words: prologue.header.packet_size_words,
        });
    }

    let payload = &input[PROLOGUE_BYTES..];
    let pad_bit_count = prologue.class_id.pad_bit_count;
    if pad_bit_count != 0 && !profile.permits_data_padding(information_class, packet_class) {
        return Err(ParseError::PadBitsNotAllowed {
            information_class,
            packet_class,
            pad_bit_count,
        });
    }
    validate_data_padding(payload, pad_bit_count)?;

    Ok(SignalDataPacket { prologue, payload })
}

fn parse_signal_context(
    input: &[u8],
    prologue: Prologue,
    profile: StandardProfile,
) -> Result<SignalContextPacket> {
    profile.expect_packet_size(
        PacketLayout::SignalContext,
        prologue.class_id.packet_class,
        prologue.header.packet_size_words,
    )?;
    expect_no_padding(prologue)?;

    let cif0 = read_u32_be(input, 7)?;
    profile.expect_signal_context_cif0(cif0)?;
    let bandwidth = FixedU64(read_u64_be(input, 9)?);
    let sample_rate = FixedU64(read_u64_be(input, 19)?);
    validate_fixed_integer_hz("context bandwidth", bandwidth.0)?;
    validate_fixed_integer_hz("context sample rate", sample_rate.0)?;
    let if_reference_frequency = FixedI64(read_i64_be(input, 11)?);
    let rf_reference_frequency = FixedI64(read_i64_be(input, 13)?);
    let if_band_offset = FixedI64(read_i64_be(input, 15)?);
    validate_fixed_integer_hz(
        "context IF reference frequency",
        if_reference_frequency.0 as u64,
    )?;
    validate_fixed_integer_hz(
        "context RF reference frequency",
        rf_reference_frequency.0 as u64,
    )?;
    validate_fixed_integer_hz("context IF band offset", if_band_offset.0 as u64)?;

    Ok(SignalContextPacket {
        prologue,
        cif0,
        context_changed: cif0 == CIF_CONTEXT_CHANGED,
        reference_point: read_u32_be(input, 8)?,
        bandwidth,
        if_reference_frequency,
        rf_reference_frequency,
        if_band_offset,
        scaling_level: ((read_u32_be(input, 17)? >> 16) as u16) as i16,
        reference_level: (read_u32_be(input, 17)? as u16) as i16,
        gain2: (read_u32_be(input, 18)? >> 16) as u16,
        gain1: read_u32_be(input, 18)? as u16,
        sample_rate,
        timestamp_adjustment: FixedI64(read_i64_be(input, 21)?),
        timestamp_calibration_time: read_u32_be(input, 23)?,
        state_and_event_indicators: read_u32_be(input, 24)?,
        payload_format: PayloadFormat::parse(read_u32_be(input, 25)?, read_u32_be(input, 26)?)?,
    })
}

fn parse_version_context(
    input: &[u8],
    prologue: Prologue,
    profile: StandardProfile,
) -> Result<crate::VersionContextPacket> {
    profile.expect_packet_size(
        PacketLayout::VersionContext,
        prologue.class_id.packet_class,
        prologue.header.packet_size_words,
    )?;
    expect_no_padding(prologue)?;

    let cif0 = read_u32_be(input, 7)?;
    profile.expect_version_context_cif0(cif0)?;
    let cif1 = read_u32_be(input, 8)?;
    profile.expect_version_context_cif1(cif1)?;
    let vita49_spec_version = read_u32_be(input, 9)?;
    profile.expect_vita49_spec_version(vita49_spec_version)?;

    let version_word = read_u32_be(input, 10)?;
    let device_type = ((version_word >> 6) & 0xF) as u8;
    let icd_version_code = (version_word & 0x3F) as u8;
    if device_type != 0 {
        return Err(ParseError::InvalidFieldValue {
            field: "version device type",
            expected: 0,
            actual: device_type as u32,
        });
    }
    if icd_version_code != DifiVersionCode::Version1 as u8 {
        return Err(ParseError::InvalidFieldValue {
            field: "DIFI ICD version",
            expected: DifiVersionCode::Version1 as u32,
            actual: icd_version_code as u32,
        });
    }

    Ok(crate::VersionContextPacket {
        prologue,
        cif0,
        context_changed: cif0 == CIF_VERSION_CHANGED,
        cif1,
        vita49_spec_version,
        year: ((version_word >> 25) & 0x7F) as u8,
        day: ((version_word >> 16) & 0x1FF) as u16,
        revision: ((version_word >> 10) & 0x3F) as u8,
        device_type,
        icd_version: DifiVersionCode::Version1,
    })
}

fn parse_timing_flow_control(
    input: &[u8],
    prologue: Prologue,
    profile: StandardProfile,
) -> Result<TimingFlowControlPacket> {
    profile.expect_packet_size(
        PacketLayout::TimingFlowControl,
        prologue.class_id.packet_class,
        prologue.header.packet_size_words,
    )?;
    expect_no_padding(prologue)?;

    let common = parse_common(input)?;
    profile.expect_timing_flow_control_cam(common.cam)?;
    let cif0 = read_u32_be(input, 11)?;
    let cif1 = read_u32_be(input, 12)?;
    profile.expect_timing_flow_control_cif0(cif0)?;
    profile.expect_timing_flow_control_cif1(cif1)?;

    let sample_rate_raw = read_u64_be(input, 14)?;
    validate_fixed_integer_hz("timing flow control sample rate", sample_rate_raw)?;
    let buffer_status_raw = read_u32_be(input, 20)?;
    if (buffer_status_raw >> 16) != 0 {
        return Err(ParseError::ReservedBitsNonZero {
            field: "buffer status",
            bits: buffer_status_raw >> 16,
        });
    }
    let buffer_level = ((buffer_status_raw >> 4) & 0x0FFF) as u16;
    let flags = (buffer_status_raw & 0xF) as u8;

    Ok(TimingFlowControlPacket {
        prologue,
        common,
        cif0,
        cif1,
        reference_point: read_u32_be(input, 13)?,
        sample_rate: FixedU64(sample_rate_raw),
        timestamp_adjustment: FixedI64(read_i64_be(input, 16)?),
        buffer_size_bytes: read_u64_be(input, 18)?,
        buffer_status: BufferStatus {
            raw: buffer_status_raw,
            buffer_level,
            overflow: (flags & 0b1000) != 0,
            nearly_full: (flags & 0b0100) != 0,
            nearly_empty: (flags & 0b0010) != 0,
            underflow: (flags & 0b0001) != 0,
        },
    })
}

fn parse_sink_capabilities_query(
    input: &[u8],
    prologue: Prologue,
    profile: StandardProfile,
) -> Result<SinkCapabilitiesQueryPacket> {
    expect_no_padding(prologue)?;
    let common = parse_common(input)?;
    profile.expect_sink_capabilities_query_cam(common.cam)?;
    let cif0 = read_u32_be(input, 11)?;
    let is_short = (cif0 & 0x8000_0000) != 0;

    if is_short {
        profile.expect_packet_size(
            PacketLayout::SinkCapabilitiesQueryShort,
            prologue.class_id.packet_class,
            prologue.header.packet_size_words,
        )?;
        profile.expect_sink_capabilities_short_query_cif0(cif0)?;
        Ok(SinkCapabilitiesQueryPacket {
            prologue,
            common,
            form: CapabilityForm::Short,
            cif0,
            cif1: None,
            sink_time_calibration_integer: Some(read_u32_be(input, 12)?),
            sink_time_calibration_fractional: Some(read_u64_be(input, 13)?),
        })
    } else {
        profile.expect_packet_size(
            PacketLayout::SinkCapabilitiesQueryLong,
            prologue.class_id.packet_class,
            prologue.header.packet_size_words,
        )?;
        profile.expect_sink_capabilities_long_query_cif0(cif0)?;
        let cif1 = read_u32_be(input, 12)?;
        profile.expect_sink_capabilities_long_query_cif1(cif1)?;
        Ok(SinkCapabilitiesQueryPacket {
            prologue,
            common,
            form: CapabilityForm::Long,
            cif0,
            cif1: Some(cif1),
            sink_time_calibration_integer: None,
            sink_time_calibration_fractional: None,
        })
    }
}

fn parse_sink_capabilities_response<'a>(
    input: &'a [u8],
    prologue: Prologue,
    profile: StandardProfile,
) -> Result<SinkCapabilitiesResponsePacket<'a>> {
    expect_no_padding(prologue)?;
    let common = parse_common(input)?;
    profile.expect_sink_capabilities_response_cam(common.cam)?;
    let cif0 = read_u32_be(input, 11)?;
    let is_short = (cif0 & 0x8000_0000) != 0;

    if is_short {
        profile.expect_packet_size(
            PacketLayout::SinkCapabilitiesResponseShort,
            prologue.class_id.packet_class,
            prologue.header.packet_size_words,
        )?;
        profile.expect_sink_capabilities_short_response_cif0(cif0)?;
        Ok(SinkCapabilitiesResponsePacket {
            prologue,
            common,
            form: CapabilityForm::Short,
            cif0,
            cif1: None,
            control_packet_integer_timestamp: Some(read_u32_be(input, 12)?),
            control_packet_fractional_timestamp: Some(read_u64_be(input, 13)?),
            sink_reception_integer_timestamp: Some(read_u32_be(input, 15)?),
            sink_reception_fractional_timestamp: Some(read_u64_be(input, 16)?),
            capability_table: &[],
        })
    } else {
        if prologue.header.packet_size_words <= 13 {
            return Err(ParseError::InvalidPacketSize {
                packet_class: prologue.class_id.packet_class,
                expected: 14,
                actual: prologue.header.packet_size_words,
            });
        }
        profile.expect_sink_capabilities_long_response_cif0(cif0)?;
        let cif1 = read_u32_be(input, 12)?;
        profile.expect_sink_capabilities_long_response_cif1(cif1)?;
        Ok(SinkCapabilitiesResponsePacket {
            prologue,
            common,
            form: CapabilityForm::Long,
            cif0,
            cif1: Some(cif1),
            control_packet_integer_timestamp: None,
            control_packet_fractional_timestamp: None,
            sink_reception_integer_timestamp: None,
            sink_reception_fractional_timestamp: None,
            capability_table: &input[13 * WORD_BYTES..],
        })
    }
}

fn parse_status_report(
    input: &[u8],
    prologue: Prologue,
    profile: StandardProfile,
) -> Result<StatusReportPacket> {
    let packet_size = prologue.header.packet_size_words;
    profile.validate_status_report_size(prologue.class_id.packet_class, packet_size)?;
    expect_no_padding(prologue)?;

    let common = parse_common(input)?;
    profile.expect_status_report_cam(common.cam)?;
    let cif0 = read_u32_be(input, 11)?;
    profile.expect_status_report_cif0(cif0)?;
    let cif1 = read_u32_be(input, 12)?;
    profile.expect_status_report_cif1(cif1)?;
    let packet_errors = read_u32_be(input, 13)?;
    let sink_errors_warnings = read_u32_be(input, 14)?;

    // Word 2 of the Status Code Payload carries two "quantitative flag" bits in its low byte:
    // bit 4 = Reference Level Limit present, bit 3 = Sample Rate & Bandwidth Limits present.
    // Cross-check them against the packet size.
    let expected_flags: u32 = match packet_size {
        15 => 0,
        17 => 0x10,
        21 => 0x18,
        _ => unreachable!("packet size already validated above"),
    };
    let actual_flags = sink_errors_warnings & 0x18;
    if actual_flags != expected_flags {
        return Err(ParseError::InvalidFieldValue {
            field: "status report quantitative flags",
            expected: expected_flags,
            actual: actual_flags,
        });
    }

    let reference_level_limit = if packet_size >= 17 {
        Some(ReferenceLevelLimit {
            raw_min_max: read_u32_be(input, 15)?,
            raw_resolution_reserved: read_u32_be(input, 16)?,
        })
    } else {
        None
    };

    let (sample_rate_limit, bandwidth_limit) = if packet_size == 21 {
        let sample_rate = read_u64_be(input, 17)?;
        let bandwidth = read_u64_be(input, 19)?;
        validate_fixed_integer_hz("status sample rate limit", sample_rate)?;
        validate_fixed_integer_hz("status bandwidth limit", bandwidth)?;
        (Some(FixedU64(sample_rate)), Some(FixedU64(bandwidth)))
    } else {
        (None, None)
    };

    Ok(StatusReportPacket {
        prologue,
        common,
        cif0,
        cif1,
        packet_errors,
        sink_errors_warnings,
        reference_level_limit,
        sample_rate_limit,
        bandwidth_limit,
    })
}

fn parse_common(input: &[u8]) -> Result<CommandCommon> {
    Ok(CommandCommon {
        cam: read_u32_be(input, 7)?,
        message_id: read_u32_be(input, 8)?,
        controllee_id: read_u32_be(input, 9)?,
        controller_id: read_u32_be(input, 10)?,
    })
}

fn expect_no_padding(prologue: Prologue) -> Result<()> {
    if prologue.class_id.pad_bit_count == 0 {
        Ok(())
    } else {
        Err(ParseError::PadBitsNotAllowed {
            information_class: prologue.class_id.information_class,
            packet_class: prologue.class_id.packet_class,
            pad_bit_count: prologue.class_id.pad_bit_count,
        })
    }
}

fn validate_data_padding(payload: &[u8], pad_bit_count: u8) -> Result<()> {
    if pad_bit_count == 0 {
        return Ok(());
    }
    let payload_bits = payload.len() * 8;
    if pad_bit_count as usize > payload_bits {
        return Err(ParseError::InvalidPadding {
            pad_bit_count,
            payload_bits,
        });
    }
    if payload.is_empty() {
        return Err(ParseError::InvalidPadding {
            pad_bit_count,
            payload_bits,
        });
    }

    let full_pad_bytes = (pad_bit_count / 8) as usize;
    let partial_pad_bits = pad_bit_count % 8;

    if full_pad_bytes != 0 {
        let start = payload.len() - full_pad_bytes;
        if payload[start..].iter().any(|byte| *byte != 0) {
            return Err(ParseError::NonZeroPaddingBits);
        }
    }

    if partial_pad_bits != 0 {
        let byte_index = payload.len() - full_pad_bytes - 1;
        let mask = (1u16 << partial_pad_bits) - 1;
        if (payload[byte_index] as u16) & mask != 0 {
            return Err(ParseError::NonZeroPaddingBits);
        }
    }

    Ok(())
}
