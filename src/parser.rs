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
use crate::validation::{
    CAM_CONTROL_EXECUTE, CAM_EXTENSION_ACK_VALIDATE, CAM_EXTENSION_CONTROL_VALIDATE,
    CIF_COMMAND_LONG, CIF_COMMAND_SHORT, CIF_CONTEXT_CHANGED, CIF_CONTEXT_UNCHANGED,
    CIF_CONTROL_FLOW_0, CIF_CONTROL_FLOW_1, CIF_VERSION_1, CIF_VERSION_CHANGED,
    CIF_VERSION_UNCHANGED, VITA49_SPEC_VERSION, expect_word, expect_word_one_of,
    validate_class_membership, validate_fixed_integer_hz, validate_header_bits,
    validate_packet_type_class, validate_tsf, validate_tsm,
};
use crate::{ClassId, DifiVersionCode, PacketClassCode, PacketHeader, PayloadFormat};

pub(crate) fn parse_packet_exact(input: &[u8]) -> Result<Packet<'_>> {
    let (packet, remainder) = parse_packet_prefix(input)?;
    if remainder.is_empty() {
        Ok(packet)
    } else {
        Err(ParseError::TrailingBytes {
            trailing: remainder.len(),
        })
    }
}

pub(crate) fn parse_packet_prefix(input: &[u8]) -> Result<(Packet<'_>, &[u8])> {
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
    let packet = parse_single_packet(packet_bytes)?;
    Ok((packet, remainder))
}

fn parse_single_packet(input: &[u8]) -> Result<Packet<'_>> {
    let header = PacketHeader::parse(read_u32_be(input, 0)?)?;
    if !header.class_id_indicator {
        return Err(ParseError::MissingClassId);
    }
    let class_id = ClassId::parse(read_u32_be(input, 2)?, read_u32_be(input, 3)?)?;
    validate_packet_type_class(header.packet_type, class_id.packet_class)?;
    validate_header_bits(header, class_id.packet_class)?;
    validate_class_membership(class_id.information_class, class_id.packet_class)?;
    validate_tsf(header, class_id.packet_class)?;
    validate_tsm(header, class_id.information_class, class_id.packet_class)?;

    let prologue = Prologue {
        header,
        stream_id: read_u32_be(input, 1)?,
        class_id,
        integer_seconds_timestamp: read_u32_be(input, 4)?,
        fractional_seconds_timestamp: read_u64_be(input, 5)?,
    };

    match class_id.packet_class {
        PacketClassCode::StandardFlowSignalData | PacketClassCode::SampleCountSignalData => {
            parse_data(input, prologue).map(Packet::SignalData)
        }
        PacketClassCode::StandardFlowSignalContext | PacketClassCode::SampleCountSignalContext => {
            parse_signal_context(input, prologue).map(Packet::SignalContext)
        }
        PacketClassCode::VersionFlowSignalContext => {
            parse_version_context(input, prologue).map(Packet::VersionContext)
        }
        PacketClassCode::SampleCountTimingFlowControl
        | PacketClassCode::RealTimeTimingFlowControl => {
            parse_timing_flow_control(input, prologue).map(Packet::TimingFlowControl)
        }
        PacketClassCode::SinkCapabilitiesQuery => {
            parse_sink_capabilities_query(input, prologue).map(Packet::SinkCapabilitiesQuery)
        }
        PacketClassCode::SinkCapabilitiesResponse => {
            parse_sink_capabilities_response(input, prologue).map(Packet::SinkCapabilitiesResponse)
        }
        PacketClassCode::StatusReport => {
            parse_status_report(input, prologue).map(Packet::StatusReport)
        }
    }
}

fn parse_data<'a>(input: &'a [u8], prologue: Prologue) -> Result<SignalDataPacket<'a>> {
    let packet_class = prologue.class_id.packet_class;
    let information_class = prologue.class_id.information_class;
    if prologue.header.packet_size_words < PROLOGUE_WORDS {
        return Err(ParseError::PacketSizeTooSmall {
            words: prologue.header.packet_size_words,
        });
    }

    let payload = &input[PROLOGUE_BYTES..];
    let pad_bit_count = prologue.class_id.pad_bit_count;
    if pad_bit_count != 0 && !information_class.permits_data_padding(packet_class) {
        return Err(ParseError::PadBitsNotAllowed {
            information_class,
            packet_class,
            pad_bit_count,
        });
    }
    validate_data_padding(payload, pad_bit_count)?;

    Ok(SignalDataPacket { prologue, payload })
}

fn parse_signal_context(input: &[u8], prologue: Prologue) -> Result<SignalContextPacket> {
    expect_size(
        prologue.class_id.packet_class,
        27,
        prologue.header.packet_size_words,
    )?;
    expect_no_padding(prologue)?;

    let cif0 = read_u32_be(input, 7)?;
    expect_word_one_of(
        "signal context CIF0",
        cif0,
        &[CIF_CONTEXT_CHANGED, CIF_CONTEXT_UNCHANGED],
    )?;
    let bandwidth = FixedU64(read_u64_be(input, 9)?);
    let sample_rate = FixedU64(read_u64_be(input, 19)?);
    validate_fixed_integer_hz("context bandwidth", bandwidth.0)?;
    validate_fixed_integer_hz("context sample rate", sample_rate.0)?;

    Ok(SignalContextPacket {
        prologue,
        cif0,
        context_changed: cif0 == CIF_CONTEXT_CHANGED,
        reference_point: read_u32_be(input, 8)?,
        bandwidth,
        if_reference_frequency: FixedI64(read_i64_be(input, 11)?),
        rf_reference_frequency: FixedI64(read_i64_be(input, 13)?),
        if_band_offset: FixedI64(read_i64_be(input, 15)?),
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

fn parse_version_context(input: &[u8], prologue: Prologue) -> Result<crate::VersionContextPacket> {
    expect_size(
        prologue.class_id.packet_class,
        11,
        prologue.header.packet_size_words,
    )?;
    expect_no_padding(prologue)?;

    let cif0 = read_u32_be(input, 7)?;
    expect_word_one_of(
        "version context CIF0",
        cif0,
        &[CIF_VERSION_CHANGED, CIF_VERSION_UNCHANGED],
    )?;
    let cif1 = read_u32_be(input, 8)?;
    expect_word("version context CIF1", CIF_VERSION_1, cif1)?;
    let vita49_spec_version = read_u32_be(input, 9)?;
    expect_word(
        "VITA 49.2 spec version",
        VITA49_SPEC_VERSION,
        vita49_spec_version,
    )?;

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

fn parse_timing_flow_control(input: &[u8], prologue: Prologue) -> Result<TimingFlowControlPacket> {
    expect_size(
        prologue.class_id.packet_class,
        21,
        prologue.header.packet_size_words,
    )?;
    expect_no_padding(prologue)?;

    let common = parse_common(input)?;
    expect_word("timing flow control CAM", CAM_CONTROL_EXECUTE, common.cam)?;
    let cif0 = read_u32_be(input, 11)?;
    let cif1 = read_u32_be(input, 12)?;
    expect_word("timing flow control CIF0", CIF_CONTROL_FLOW_0, cif0)?;
    expect_word("timing flow control CIF1", CIF_CONTROL_FLOW_1, cif1)?;

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
) -> Result<SinkCapabilitiesQueryPacket> {
    expect_no_padding(prologue)?;
    let common = parse_common(input)?;
    expect_word(
        "sink capabilities query CAM",
        CAM_EXTENSION_CONTROL_VALIDATE,
        common.cam,
    )?;
    let cif0 = read_u32_be(input, 11)?;
    let is_short = (cif0 & 0x8000_0000) != 0;

    if is_short {
        expect_size(
            prologue.class_id.packet_class,
            15,
            prologue.header.packet_size_words,
        )?;
        expect_word(
            "sink capabilities short query CIF0",
            CIF_COMMAND_SHORT,
            cif0,
        )?;
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
        expect_size(
            prologue.class_id.packet_class,
            13,
            prologue.header.packet_size_words,
        )?;
        expect_word("sink capabilities long query CIF0", CIF_COMMAND_LONG, cif0)?;
        let cif1 = read_u32_be(input, 12)?;
        expect_word(
            "sink capabilities long query CIF1",
            CIF_CONTROL_FLOW_1,
            cif1,
        )?;
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
) -> Result<SinkCapabilitiesResponsePacket<'a>> {
    expect_no_padding(prologue)?;
    let common = parse_common(input)?;
    expect_word(
        "sink capabilities response CAM",
        CAM_EXTENSION_ACK_VALIDATE,
        common.cam,
    )?;
    let cif0 = read_u32_be(input, 11)?;
    let is_short = (cif0 & 0x8000_0000) != 0;

    if is_short {
        expect_size(
            prologue.class_id.packet_class,
            18,
            prologue.header.packet_size_words,
        )?;
        expect_word(
            "sink capabilities short response CIF0",
            CIF_COMMAND_SHORT,
            cif0,
        )?;
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
        expect_word(
            "sink capabilities long response CIF0",
            CIF_COMMAND_LONG,
            cif0,
        )?;
        let cif1 = read_u32_be(input, 12)?;
        expect_word(
            "sink capabilities long response CIF1",
            CIF_CONTROL_FLOW_1,
            cif1,
        )?;
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

fn parse_status_report(input: &[u8], prologue: Prologue) -> Result<StatusReportPacket> {
    const STATUS_SIZES: &[u16] = &[15, 17, 21];
    if !STATUS_SIZES.contains(&prologue.header.packet_size_words) {
        return Err(ParseError::InvalidPacketSizeSet {
            packet_class: prologue.class_id.packet_class,
            expected: STATUS_SIZES,
            actual: prologue.header.packet_size_words,
        });
    }
    expect_no_padding(prologue)?;

    let common = parse_common(input)?;
    let cif0 = read_u32_be(input, 11)?;
    expect_word("status report CIF0", 0, cif0)?;
    let status_words = [
        read_u32_be(input, 12)?,
        read_u32_be(input, 13)?,
        read_u32_be(input, 14)?,
    ];

    let reference_level_limit = if prologue.header.packet_size_words >= 17 {
        Some(ReferenceLevelLimit {
            raw_min_max: read_u32_be(input, 15)?,
            raw_resolution_reserved: read_u32_be(input, 16)?,
        })
    } else {
        None
    };

    let (sample_rate_limit, bandwidth_limit) = if prologue.header.packet_size_words == 21 {
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
        status_words,
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

fn expect_size(packet_class: PacketClassCode, expected: u16, actual: u16) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(ParseError::InvalidPacketSize {
            packet_class,
            expected,
            actual,
        })
    }
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
