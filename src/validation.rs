use crate::error::{ParseError, Result};
use crate::{InformationClassCode, PacketClassCode, PacketHeader, PacketType, TimestampMode, Tsf};

pub(crate) const CIF_CONTEXT_CHANGED: u32 = 0xFBB9_8000;
pub(crate) const CIF_CONTEXT_UNCHANGED: u32 = 0x7BB9_8000;
pub(crate) const CIF_VERSION_CHANGED: u32 = 0x8000_0002;
pub(crate) const CIF_VERSION_UNCHANGED: u32 = 0x0000_0002;
pub(crate) const CIF_VERSION_1: u32 = 0x0000_000C;
pub(crate) const VITA49_SPEC_VERSION: u32 = 0x0000_0004;
pub(crate) const CAM_CONTROL_EXECUTE: u32 = 0xA100_0000;
pub(crate) const CAM_EXTENSION_CONTROL_VALIDATE: u32 = 0xA110_0000;
pub(crate) const CAM_EXTENSION_ACK_VALIDATE: u32 = 0xA110_0400;
pub(crate) const CIF_COMMAND_LONG: u32 = 0x7BB9_8002;
pub(crate) const CIF_COMMAND_SHORT: u32 = 0x8000_0000;
pub(crate) const CIF_CONTROL_FLOW_0: u32 = 0x4030_0002;
pub(crate) const CIF_CONTROL_FLOW_1: u32 = 0x0000_0002;

pub(crate) fn validate_class_membership(
    information_class: InformationClassCode,
    packet_class: PacketClassCode,
) -> Result<()> {
    if information_class.allows_packet_class(packet_class) {
        Ok(())
    } else {
        Err(ParseError::PacketClassNotInInformationClass {
            information_class,
            packet_class,
        })
    }
}

pub(crate) fn validate_packet_type_class(
    packet_type: PacketType,
    packet_class: PacketClassCode,
) -> Result<()> {
    let valid = match packet_type {
        PacketType::SignalDataWithStreamId => matches!(
            packet_class,
            PacketClassCode::StandardFlowSignalData | PacketClassCode::SampleCountSignalData
        ),
        PacketType::ContextWithStreamId => matches!(
            packet_class,
            PacketClassCode::StandardFlowSignalContext
                | PacketClassCode::SampleCountSignalContext
                | PacketClassCode::VersionFlowSignalContext
        ),
        PacketType::CommandWithStreamId => matches!(
            packet_class,
            PacketClassCode::SampleCountTimingFlowControl
                | PacketClassCode::RealTimeTimingFlowControl
        ),
        PacketType::ExtensionCommandWithStreamId => matches!(
            packet_class,
            PacketClassCode::SinkCapabilitiesQuery
                | PacketClassCode::SinkCapabilitiesResponse
                | PacketClassCode::StatusReport
        ),
    };

    if valid {
        Ok(())
    } else {
        Err(ParseError::PacketTypeClassMismatch {
            packet_type,
            packet_class,
        })
    }
}

pub(crate) fn validate_header_bits(
    header: PacketHeader,
    packet_class: PacketClassCode,
) -> Result<()> {
    if !header.class_id_indicator {
        return Err(ParseError::MissingClassId);
    }

    match header.packet_type {
        PacketType::SignalDataWithStreamId | PacketType::CommandWithStreamId => {
            expect_bits("packet header type-specific", 0, header.type_specific_bits)?;
        }
        PacketType::ContextWithStreamId => {
            let reserved = header.type_specific_bits & 0b110;
            if reserved != 0 {
                return Err(ParseError::ReservedBitsNonZero {
                    field: "context packet header",
                    bits: reserved as u32,
                });
            }
        }
        PacketType::ExtensionCommandWithStreamId => {
            let expected = match packet_class {
                PacketClassCode::SinkCapabilitiesResponse => 0b100,
                PacketClassCode::SinkCapabilitiesQuery | PacketClassCode::StatusReport => 0,
                _ => header.type_specific_bits,
            };
            expect_bits(
                "extension command header type-specific",
                expected,
                header.type_specific_bits,
            )?;
        }
    }

    Ok(())
}

pub(crate) fn validate_tsf(header: PacketHeader, packet_class: PacketClassCode) -> Result<()> {
    let expected = match packet_class {
        PacketClassCode::StandardFlowSignalData
        | PacketClassCode::StandardFlowSignalContext
        | PacketClassCode::VersionFlowSignalContext
        | PacketClassCode::RealTimeTimingFlowControl => Some(Tsf::RealTimePicoseconds),
        PacketClassCode::SampleCountSignalData
        | PacketClassCode::SampleCountSignalContext
        | PacketClassCode::SampleCountTimingFlowControl => Some(Tsf::SampleCount),
        PacketClassCode::SinkCapabilitiesQuery
        | PacketClassCode::SinkCapabilitiesResponse
        | PacketClassCode::StatusReport => None,
    };

    if let Some(expected) = expected
        && header.tsf != expected
    {
        return Err(ParseError::InvalidTsfForPacketClass {
            packet_class,
            expected,
            actual: header.tsf,
        });
    }

    Ok(())
}

pub(crate) fn validate_tsm(
    header: PacketHeader,
    information_class: InformationClassCode,
    packet_class: PacketClassCode,
) -> Result<()> {
    let Some(actual) = header.tsm else {
        return Ok(());
    };

    let expected = match packet_class {
        PacketClassCode::StandardFlowSignalContext => match information_class {
            InformationClassCode::BasicDataPlane
            | InformationClassCode::BasicDataPlaneWithLinkEstablishment => TimestampMode::Coarse,
            _ => TimestampMode::Fine,
        },
        PacketClassCode::SampleCountSignalContext => TimestampMode::Fine,
        PacketClassCode::VersionFlowSignalContext => TimestampMode::Coarse,
        _ => return Ok(()),
    };

    if actual == expected {
        Ok(())
    } else {
        Err(ParseError::InvalidHeaderBits {
            field: "timestamp mode",
            expected: expected as u8,
            actual: actual as u8,
        })
    }
}

pub(crate) fn validate_fixed_integer_hz(field: &'static str, raw: u64) -> Result<()> {
    if raw & ((1 << 20) - 1) == 0 {
        Ok(())
    } else {
        Err(ParseError::FractionalHzNotAllowed { field, raw })
    }
}

pub(crate) fn expect_word(field: &'static str, expected: u32, actual: u32) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(ParseError::InvalidFieldValue {
            field,
            expected,
            actual,
        })
    }
}

pub(crate) fn expect_word_one_of(field: &'static str, actual: u32, allowed: &[u32]) -> Result<()> {
    if allowed.contains(&actual) {
        Ok(())
    } else {
        Err(ParseError::InvalidFieldValueSet { field, actual })
    }
}

fn expect_bits(field: &'static str, expected: u8, actual: u8) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(ParseError::InvalidHeaderBits {
            field,
            expected,
            actual,
        })
    }
}
