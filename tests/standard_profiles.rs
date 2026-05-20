mod common;

use difi::{
    CompatibilityMode, DifiStandardVersion, InformationClassCode, Packet, PacketClassCode,
    PacketType, ParseError, ParseOptions, parse_packet_exact, parse_packet_exact_with_options,
};

use common::{
    CAM_CONTROL_EXECUTE, CAM_STATUS_REPORT_EXECUTE, CIF_CONTROL_FLOW_0, CIF_CONTROL_FLOW_1, bytes,
    class_id, fixed_hz, header, signed_words,
};

fn options(standard: DifiStandardVersion, compatibility: CompatibilityMode) -> ParseOptions {
    ParseOptions {
        standard,
        compatibility,
    }
}

fn strict(standard: DifiStandardVersion) -> ParseOptions {
    options(standard, CompatibilityMode::Strict)
}

fn version_context(packet_type: u8) -> Vec<u8> {
    let [cid0, cid1] = class_id(0x0001, 0x0004, 0);
    let version_word = (26 << 25) | (130 << 16) | (1 << 10);

    bytes(&[
        header(packet_type, 0x1, 0x1, 0x2, 0, 11),
        0xCAFE_BABE,
        cid0,
        cid1,
        1,
        0,
        2,
        0x8000_0002,
        0x0000_000C,
        0x0000_0004,
        version_word,
    ])
}

fn sample_count_data() -> Vec<u8> {
    let [cid0, cid1] = class_id(0x0002, 0x0002, 0);

    bytes(&[
        header(0x1, 0, 0x1, 0x1, 0, 8),
        0x0102_0304,
        cid0,
        cid1,
        0,
        0,
        1,
        0xABCD_EF01,
    ])
}

fn sample_count_data_for_information_class(information_class: u16) -> Vec<u8> {
    let [cid0, cid1] = class_id(information_class, 0x0002, 0);

    bytes(&[
        header(0x1, 0, 0x1, 0x1, 0, 8),
        0x0102_0304,
        cid0,
        cid1,
        0,
        0,
        1,
        0xABCD_EF01,
    ])
}

fn timing_flow_control() -> Vec<u8> {
    let [cid0, cid1] = class_id(0x0002, 0x0005, 0);
    let sample_rate = fixed_hz(40_000_000);
    let timestamp_adjustment = signed_words(250);

    bytes(&[
        header(0x6, 0, 0x1, 0x1, 0, 21),
        0x0102_0304,
        cid0,
        cid1,
        10,
        0,
        11,
        CAM_CONTROL_EXECUTE,
        7,
        8,
        9,
        CIF_CONTROL_FLOW_0,
        CIF_CONTROL_FLOW_1,
        100,
        sample_rate[0],
        sample_rate[1],
        timestamp_adjustment[0],
        timestamp_adjustment[1],
        0,
        4096,
        (0x0ABC << 4) | 0b1010,
    ])
}

fn real_time_timing_flow_control_for_information_class(information_class: u16) -> Vec<u8> {
    let [cid0, cid1] = class_id(information_class, 0x0006, 0);
    let sample_rate = fixed_hz(40_000_000);
    let timestamp_adjustment = signed_words(250);

    bytes(&[
        header(0x6, 0, 0x1, 0x2, 0, 21),
        0x0102_0304,
        cid0,
        cid1,
        10,
        0,
        11,
        CAM_CONTROL_EXECUTE,
        7,
        8,
        9,
        CIF_CONTROL_FLOW_0,
        CIF_CONTROL_FLOW_1,
        100,
        sample_rate[0],
        sample_rate[1],
        timestamp_adjustment[0],
        timestamp_adjustment[1],
        0,
        4096,
        (0x0ABC << 4) | 0b1010,
    ])
}

fn status_report() -> Vec<u8> {
    let [cid0, cid1] = class_id(0x0100, 0x0009, 0);

    bytes(&[
        header(0x7, 0, 0x1, 0x2, 0, 15),
        0,
        cid0,
        cid1,
        0,
        0,
        0,
        CAM_STATUS_REPORT_EXECUTE,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ])
}

fn standalone_status_report() -> Vec<u8> {
    let [cid0, cid1] = class_id(0x0101, 0x0009, 0);

    bytes(&[
        header(0x7, 0, 0x1, 0x2, 0, 15),
        0,
        cid0,
        cid1,
        0,
        0,
        0,
        CAM_STATUS_REPORT_EXECUTE,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ])
}

#[test]
fn defaults_to_strict_v1_3_profile() {
    let packet = version_context(0x4);
    assert!(parse_packet_exact(&packet).is_ok());

    let legacy = version_context(0x5);
    assert!(matches!(
        parse_packet_exact(&legacy).unwrap_err(),
        ParseError::PacketTypeNotAvailableInStandard {
            standard: DifiStandardVersion::V1_3_0,
            packet_type: PacketType::VersionWithStreamId
        }
    ));
}

#[test]
fn v1_1_accepts_legacy_version_packet_type() {
    let input = version_context(0x5);
    let Packet::VersionContext(packet) =
        parse_packet_exact_with_options(&input, strict(DifiStandardVersion::V1_1))
            .expect("valid v1.1 version packet")
    else {
        panic!("expected version context");
    };

    assert_eq!(
        packet.prologue.header.packet_type,
        PacketType::VersionWithStreamId
    );
    assert_eq!(
        packet.prologue.class_id.packet_class,
        PacketClassCode::VersionFlowSignalContext
    );
}

#[test]
fn v1_1_rejects_context_packet_type_for_version_context() {
    let input = version_context(0x4);

    assert!(matches!(
        parse_packet_exact_with_options(&input, strict(DifiStandardVersion::V1_1)).unwrap_err(),
        ParseError::PacketTypeClassMismatch {
            packet_type: PacketType::ContextWithStreamId,
            packet_class: PacketClassCode::VersionFlowSignalContext
        }
    ));
}

#[test]
fn v1_2_strict_and_legacy_modes_handle_version_packet_type() {
    let context_type = version_context(0x4);
    assert!(
        parse_packet_exact_with_options(&context_type, strict(DifiStandardVersion::V1_2_1)).is_ok()
    );

    let legacy_type = version_context(0x5);
    assert!(matches!(
        parse_packet_exact_with_options(&legacy_type, strict(DifiStandardVersion::V1_2_1))
            .unwrap_err(),
        ParseError::PacketTypeNotAvailableInStandard {
            standard: DifiStandardVersion::V1_2_1,
            packet_type: PacketType::VersionWithStreamId
        }
    ));

    assert!(
        parse_packet_exact_with_options(
            &legacy_type,
            options(
                DifiStandardVersion::V1_2_1,
                CompatibilityMode::LegacyVersionPacketType,
            ),
        )
        .is_ok()
    );
}

#[test]
fn v1_1_rejects_sample_count_and_command_classes() {
    assert!(matches!(
        parse_packet_exact_with_options(&sample_count_data(), strict(DifiStandardVersion::V1_1))
            .unwrap_err(),
        ParseError::PacketClassNotAvailableInStandard {
            standard: DifiStandardVersion::V1_1,
            packet_class: PacketClassCode::SampleCountSignalData
        }
    ));

    assert!(matches!(
        parse_packet_exact_with_options(&timing_flow_control(), strict(DifiStandardVersion::V1_1))
            .unwrap_err(),
        ParseError::PacketTypeNotAvailableInStandard {
            standard: DifiStandardVersion::V1_1,
            packet_type: PacketType::CommandWithStreamId
        }
    ));
}

#[test]
fn v1_2_accepts_timing_flow_control_but_rejects_link_establishment() {
    assert!(
        parse_packet_exact_with_options(&sample_count_data(), strict(DifiStandardVersion::V1_2_1))
            .is_ok()
    );
    assert!(
        parse_packet_exact_with_options(
            &timing_flow_control(),
            strict(DifiStandardVersion::V1_2_1),
        )
        .is_ok()
    );
    assert!(
        parse_packet_exact_with_options(
            &real_time_timing_flow_control_for_information_class(0x0003),
            strict(DifiStandardVersion::V1_2_1),
        )
        .is_ok()
    );

    assert!(matches!(
        parse_packet_exact_with_options(&status_report(), strict(DifiStandardVersion::V1_2_1))
            .unwrap_err(),
        ParseError::PacketTypeNotAvailableInStandard {
            standard: DifiStandardVersion::V1_2_1,
            packet_type: PacketType::ExtensionCommandWithStreamId
        }
    ));
}

#[test]
fn v1_3_accepts_downstream_sample_count_and_real_time_link_establishment_classes() {
    let downstream_sample_count = sample_count_data_for_information_class(0x0005);
    let Packet::SignalData(data) =
        parse_packet_exact(&downstream_sample_count).expect("valid downstream sample-count data")
    else {
        panic!("expected signal data");
    };
    assert_eq!(
        data.prologue.class_id.information_class,
        InformationClassCode::DataPlaneDownstreamFlowControlSampleCount
    );

    let downstream_real_time_link = real_time_timing_flow_control_for_information_class(0x0106);
    let Packet::TimingFlowControl(flow_control) = parse_packet_exact(&downstream_real_time_link)
        .expect("valid downstream real-time flow control with link establishment")
    else {
        panic!("expected timing flow control");
    };
    assert_eq!(
        flow_control.prologue.class_id.information_class,
        InformationClassCode::DataPlaneDownstreamFlowControlRealTimeWithLinkEstablishment
    );
    assert_eq!(
        flow_control.prologue.class_id.packet_class,
        PacketClassCode::RealTimeTimingFlowControl
    );
}

#[test]
fn v1_3_rejects_link_establishment_class_membership_mismatch() {
    assert_eq!(
        parse_packet_exact(&standalone_status_report()).unwrap_err(),
        ParseError::PacketClassNotInInformationClass {
            information_class: InformationClassCode::StandaloneLinkEstablishment,
            packet_class: PacketClassCode::StatusReport
        }
    );
}
