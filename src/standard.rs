use crate::error::{ParseError, Result};
use crate::validation::{expect_bits, expect_word, expect_word_one_of};
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
pub(crate) const CAM_STATUS_REPORT_EXECUTE: u32 = 0xA108_0000;
pub(crate) const CIF_COMMAND_LONG: u32 = 0x7BB9_8002;
pub(crate) const CIF_COMMAND_SHORT: u32 = 0x8000_0000;
pub(crate) const CIF_CONTROL_FLOW_0: u32 = 0x4030_0002;
pub(crate) const CIF_CONTROL_FLOW_1: u32 = 0x0000_0002;

const STATUS_REPORT_SIZES: &[u16] = &[15, 17, 21];

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DifiStandardVersion {
    V1_1,
    V1_2_1,
    V1_3_0,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CompatibilityMode {
    Strict,
    LegacyVersionPacketType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ParseOptions {
    pub standard: DifiStandardVersion,
    pub compatibility: CompatibilityMode,
}

impl ParseOptions {
    pub const DEFAULT: Self = Self {
        standard: DifiStandardVersion::V1_3_0,
        compatibility: CompatibilityMode::Strict,
    };
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PacketLayout {
    SignalContext,
    VersionContext,
    TimingFlowControl,
    SinkCapabilitiesQueryLong,
    SinkCapabilitiesQueryShort,
    SinkCapabilitiesResponseShort,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StandardProfile {
    options: ParseOptions,
}

impl StandardProfile {
    pub(crate) const fn new(options: ParseOptions) -> Self {
        Self { options }
    }

    pub(crate) fn validate_packet_type_available(self, packet_type: PacketType) -> Result<()> {
        if self.packet_type_available(packet_type) {
            Ok(())
        } else {
            Err(ParseError::PacketTypeNotAvailableInStandard {
                standard: self.options.standard,
                packet_type,
            })
        }
    }

    pub(crate) fn validate_packet_class_available(
        self,
        packet_class: PacketClassCode,
    ) -> Result<()> {
        if self.packet_class_available(packet_class) {
            Ok(())
        } else {
            Err(ParseError::PacketClassNotAvailableInStandard {
                standard: self.options.standard,
                packet_class,
            })
        }
    }

    pub(crate) fn validate_packet_type_class(
        self,
        packet_type: PacketType,
        packet_class: PacketClassCode,
    ) -> Result<()> {
        let valid = match packet_type {
            PacketType::SignalDataWithStreamId => matches!(
                packet_class,
                PacketClassCode::StandardFlowSignalData | PacketClassCode::SampleCountSignalData
            ),
            PacketType::ContextWithStreamId => match packet_class {
                PacketClassCode::StandardFlowSignalContext
                | PacketClassCode::SampleCountSignalContext => true,
                PacketClassCode::VersionFlowSignalContext => {
                    !matches!(self.options.standard, DifiStandardVersion::V1_1)
                }
                _ => false,
            },
            PacketType::VersionWithStreamId => {
                packet_class == PacketClassCode::VersionFlowSignalContext
                    && (self.options.standard == DifiStandardVersion::V1_1
                        || (self.options.standard == DifiStandardVersion::V1_2_1
                            && self.options.compatibility
                                == CompatibilityMode::LegacyVersionPacketType))
            }
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
        self,
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
            PacketType::ContextWithStreamId | PacketType::VersionWithStreamId => {
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

    pub(crate) fn validate_class_membership(
        self,
        information_class: InformationClassCode,
        packet_class: PacketClassCode,
    ) -> Result<()> {
        if self.allows_packet_class(information_class, packet_class) {
            Ok(())
        } else {
            Err(ParseError::PacketClassNotInInformationClass {
                information_class,
                packet_class,
            })
        }
    }

    pub(crate) fn validate_tsf(
        self,
        header: PacketHeader,
        packet_class: PacketClassCode,
    ) -> Result<()> {
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
        self,
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
                | InformationClassCode::BasicDataPlaneWithLinkEstablishment => {
                    TimestampMode::Coarse
                }
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

    pub(crate) fn permits_data_padding(
        self,
        information_class: InformationClassCode,
        packet_class: PacketClassCode,
    ) -> bool {
        if self.options.standard == DifiStandardVersion::V1_1 {
            return false;
        }

        let disallowed_basic_flow = matches!(
            (information_class, packet_class),
            (
                InformationClassCode::BasicDataPlane
                    | InformationClassCode::BasicDataPlaneWithLinkEstablishment,
                PacketClassCode::StandardFlowSignalData
            )
        );

        !disallowed_basic_flow
            && matches!(
                packet_class,
                PacketClassCode::StandardFlowSignalData | PacketClassCode::SampleCountSignalData
            )
    }

    pub(crate) fn expect_packet_size(
        self,
        layout: PacketLayout,
        packet_class: PacketClassCode,
        actual: u16,
    ) -> Result<()> {
        let expected = match layout {
            PacketLayout::SignalContext => 27,
            PacketLayout::VersionContext => 11,
            PacketLayout::TimingFlowControl => 21,
            PacketLayout::SinkCapabilitiesQueryLong => 13,
            PacketLayout::SinkCapabilitiesQueryShort => 15,
            PacketLayout::SinkCapabilitiesResponseShort => 18,
        };

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

    pub(crate) fn validate_status_report_size(
        self,
        packet_class: PacketClassCode,
        actual: u16,
    ) -> Result<()> {
        if STATUS_REPORT_SIZES.contains(&actual) {
            Ok(())
        } else {
            Err(ParseError::InvalidPacketSizeSet {
                packet_class,
                expected: STATUS_REPORT_SIZES,
                actual,
            })
        }
    }

    pub(crate) fn expect_signal_context_cif0(self, actual: u32) -> Result<()> {
        expect_word_one_of(
            "signal context CIF0",
            actual,
            &[CIF_CONTEXT_CHANGED, CIF_CONTEXT_UNCHANGED],
        )
    }

    pub(crate) fn expect_version_context_cif0(self, actual: u32) -> Result<()> {
        expect_word_one_of(
            "version context CIF0",
            actual,
            &[CIF_VERSION_CHANGED, CIF_VERSION_UNCHANGED],
        )
    }

    pub(crate) fn expect_version_context_cif1(self, actual: u32) -> Result<()> {
        expect_word("version context CIF1", CIF_VERSION_1, actual)
    }

    pub(crate) fn expect_vita49_spec_version(self, actual: u32) -> Result<()> {
        expect_word("VITA 49.2 spec version", VITA49_SPEC_VERSION, actual)
    }

    pub(crate) fn expect_timing_flow_control_cam(self, actual: u32) -> Result<()> {
        expect_word("timing flow control CAM", CAM_CONTROL_EXECUTE, actual)
    }

    pub(crate) fn expect_timing_flow_control_cif0(self, actual: u32) -> Result<()> {
        expect_word("timing flow control CIF0", CIF_CONTROL_FLOW_0, actual)
    }

    pub(crate) fn expect_timing_flow_control_cif1(self, actual: u32) -> Result<()> {
        expect_word("timing flow control CIF1", CIF_CONTROL_FLOW_1, actual)
    }

    pub(crate) fn expect_sink_capabilities_query_cam(self, actual: u32) -> Result<()> {
        expect_word(
            "sink capabilities query CAM",
            CAM_EXTENSION_CONTROL_VALIDATE,
            actual,
        )
    }

    pub(crate) fn expect_sink_capabilities_short_query_cif0(self, actual: u32) -> Result<()> {
        expect_word(
            "sink capabilities short query CIF0",
            CIF_COMMAND_SHORT,
            actual,
        )
    }

    pub(crate) fn expect_sink_capabilities_long_query_cif0(self, actual: u32) -> Result<()> {
        expect_word(
            "sink capabilities long query CIF0",
            CIF_COMMAND_LONG,
            actual,
        )
    }

    pub(crate) fn expect_sink_capabilities_long_query_cif1(self, actual: u32) -> Result<()> {
        expect_word(
            "sink capabilities long query CIF1",
            CIF_CONTROL_FLOW_1,
            actual,
        )
    }

    pub(crate) fn expect_sink_capabilities_response_cam(self, actual: u32) -> Result<()> {
        expect_word(
            "sink capabilities response CAM",
            CAM_EXTENSION_ACK_VALIDATE,
            actual,
        )
    }

    pub(crate) fn expect_sink_capabilities_short_response_cif0(self, actual: u32) -> Result<()> {
        expect_word(
            "sink capabilities short response CIF0",
            CIF_COMMAND_SHORT,
            actual,
        )
    }

    pub(crate) fn expect_sink_capabilities_long_response_cif0(self, actual: u32) -> Result<()> {
        expect_word(
            "sink capabilities long response CIF0",
            CIF_COMMAND_LONG,
            actual,
        )
    }

    pub(crate) fn expect_sink_capabilities_long_response_cif1(self, actual: u32) -> Result<()> {
        expect_word(
            "sink capabilities long response CIF1",
            CIF_CONTROL_FLOW_1,
            actual,
        )
    }

    pub(crate) fn expect_status_report_cam(self, actual: u32) -> Result<()> {
        expect_word("status report CAM", CAM_STATUS_REPORT_EXECUTE, actual)
    }

    pub(crate) fn expect_status_report_cif0(self, actual: u32) -> Result<()> {
        expect_word("status report CIF0", 0, actual)
    }

    pub(crate) fn expect_status_report_cif1(self, actual: u32) -> Result<()> {
        expect_word("status report CIF1", 0, actual)
    }

    fn packet_type_available(self, packet_type: PacketType) -> bool {
        match self.options.standard {
            DifiStandardVersion::V1_1 => matches!(
                packet_type,
                PacketType::SignalDataWithStreamId
                    | PacketType::ContextWithStreamId
                    | PacketType::VersionWithStreamId
            ),
            DifiStandardVersion::V1_2_1 => {
                matches!(
                    packet_type,
                    PacketType::SignalDataWithStreamId
                        | PacketType::ContextWithStreamId
                        | PacketType::CommandWithStreamId
                ) || (packet_type == PacketType::VersionWithStreamId
                    && self.options.compatibility == CompatibilityMode::LegacyVersionPacketType)
            }
            DifiStandardVersion::V1_3_0 => matches!(
                packet_type,
                PacketType::SignalDataWithStreamId
                    | PacketType::ContextWithStreamId
                    | PacketType::CommandWithStreamId
                    | PacketType::ExtensionCommandWithStreamId
            ),
        }
    }

    fn packet_class_available(self, packet_class: PacketClassCode) -> bool {
        match self.options.standard {
            DifiStandardVersion::V1_1 => matches!(
                packet_class,
                PacketClassCode::StandardFlowSignalData
                    | PacketClassCode::StandardFlowSignalContext
                    | PacketClassCode::VersionFlowSignalContext
            ),
            DifiStandardVersion::V1_2_1 => matches!(
                packet_class,
                PacketClassCode::StandardFlowSignalData
                    | PacketClassCode::StandardFlowSignalContext
                    | PacketClassCode::SampleCountSignalData
                    | PacketClassCode::SampleCountSignalContext
                    | PacketClassCode::VersionFlowSignalContext
                    | PacketClassCode::SampleCountTimingFlowControl
                    | PacketClassCode::RealTimeTimingFlowControl
            ),
            DifiStandardVersion::V1_3_0 => true,
        }
    }

    fn allows_packet_class(
        self,
        information_class: InformationClassCode,
        packet_class: PacketClassCode,
    ) -> bool {
        use InformationClassCode as I;
        use PacketClassCode as P;

        match self.options.standard {
            DifiStandardVersion::V1_1 => match information_class {
                I::BasicDataPlane => matches!(
                    packet_class,
                    P::StandardFlowSignalData | P::StandardFlowSignalContext
                ),
                I::VersionFlow => matches!(packet_class, P::VersionFlowSignalContext),
                _ => false,
            },
            DifiStandardVersion::V1_2_1 => match information_class {
                I::BasicDataPlane => matches!(
                    packet_class,
                    P::StandardFlowSignalData | P::StandardFlowSignalContext
                ),
                I::VersionFlow => matches!(packet_class, P::VersionFlowSignalContext),
                I::DataPlaneUpstreamFlowControlSampleCount
                | I::DataPlaneDownstreamFlowControlSampleCount => matches!(
                    packet_class,
                    P::SampleCountSignalData
                        | P::SampleCountSignalContext
                        | P::SampleCountTimingFlowControl
                ),
                I::DataPlaneUpstreamFlowControlRealTime
                | I::DataPlaneDownstreamFlowControlRealTime => matches!(
                    packet_class,
                    P::StandardFlowSignalData
                        | P::StandardFlowSignalContext
                        | P::RealTimeTimingFlowControl
                ),
                I::BasicDataPlaneSampleCount => matches!(
                    packet_class,
                    P::SampleCountSignalData | P::SampleCountSignalContext
                ),
                _ => false,
            },
            DifiStandardVersion::V1_3_0 => match information_class {
                I::BasicDataPlane => matches!(
                    packet_class,
                    P::StandardFlowSignalData | P::StandardFlowSignalContext
                ),
                I::VersionFlow => matches!(packet_class, P::VersionFlowSignalContext),
                I::DataPlaneUpstreamFlowControlSampleCount
                | I::DataPlaneDownstreamFlowControlSampleCount => matches!(
                    packet_class,
                    P::SampleCountSignalData
                        | P::SampleCountSignalContext
                        | P::SampleCountTimingFlowControl
                ),
                I::DataPlaneUpstreamFlowControlRealTime
                | I::DataPlaneDownstreamFlowControlRealTime => matches!(
                    packet_class,
                    P::StandardFlowSignalData
                        | P::StandardFlowSignalContext
                        | P::RealTimeTimingFlowControl
                ),
                I::BasicDataPlaneSampleCount => matches!(
                    packet_class,
                    P::SampleCountSignalData | P::SampleCountSignalContext
                ),
                I::BasicDataPlaneWithLinkEstablishment => matches!(
                    packet_class,
                    P::StandardFlowSignalData
                        | P::StandardFlowSignalContext
                        | P::SinkCapabilitiesQuery
                        | P::SinkCapabilitiesResponse
                        | P::StatusReport
                ),
                I::StandaloneLinkEstablishment => {
                    matches!(
                        packet_class,
                        P::SinkCapabilitiesQuery | P::SinkCapabilitiesResponse
                    )
                }
                I::DataPlaneUpstreamFlowControlSampleCountWithLinkEstablishment
                | I::DataPlaneDownstreamFlowControlSampleCountWithLinkEstablishment => matches!(
                    packet_class,
                    P::SampleCountSignalData
                        | P::SampleCountSignalContext
                        | P::SampleCountTimingFlowControl
                        | P::SinkCapabilitiesQuery
                        | P::SinkCapabilitiesResponse
                        | P::StatusReport
                ),
                I::DataPlaneUpstreamFlowControlRealTimeWithLinkEstablishment
                | I::DataPlaneDownstreamFlowControlRealTimeWithLinkEstablishment => matches!(
                    packet_class,
                    P::StandardFlowSignalData
                        | P::StandardFlowSignalContext
                        | P::RealTimeTimingFlowControl
                        | P::SinkCapabilitiesQuery
                        | P::SinkCapabilitiesResponse
                        | P::StatusReport
                ),
                I::BasicDataPlaneSampleCountWithLinkEstablishment => matches!(
                    packet_class,
                    P::SampleCountSignalData
                        | P::SampleCountSignalContext
                        | P::SinkCapabilitiesQuery
                        | P::SinkCapabilitiesResponse
                        | P::StatusReport
                ),
            },
        }
    }
}
