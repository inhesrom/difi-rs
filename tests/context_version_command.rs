mod common;

use difi::{
    CapabilityForm, Packet, PacketClassCode, ParseError, TimestampMode, parse_packet_exact,
};

use common::{
    CAM_CONTROL_EXECUTE, CAM_EXTENSION_ACK_VALIDATE, CAM_EXTENSION_CONTROL_VALIDATE,
    CIF_COMMAND_LONG, CIF_COMMAND_SHORT, CIF_CONTROL_FLOW_0, CIF_CONTROL_FLOW_1, bytes, class_id,
    fixed_hz, header, payload_format, signed_words,
};

#[test]
fn parses_standard_signal_context_packet() {
    let [cid0, cid1] = class_id(0x0000, 0x0001, 0);
    let bandwidth = fixed_hz(20_000_000);
    let if_ref = signed_words(0);
    let rf_ref = signed_words(1_500_000_000_i64 << 20);
    let if_offset = signed_words(-2_000_000_i64 << 20);
    let sample_rate = fixed_hz(40_000_000);
    let timestamp_adjustment = signed_words(-1234);
    let payload_format = payload_format(16);

    let input = bytes(&[
        header(0x4, 0x1, 0x1, 0x2, 2, 27),
        0x0102_0304,
        cid0,
        cid1,
        123,
        0,
        456,
        0xFBB9_8000,
        100,
        bandwidth[0],
        bandwidth[1],
        if_ref[0],
        if_ref[1],
        rf_ref[0],
        rf_ref[1],
        if_offset[0],
        if_offset[1],
        ((0xFFF4_u16 as u32) << 16) | 0x0005,
        0,
        sample_rate[0],
        sample_rate[1],
        timestamp_adjustment[0],
        timestamp_adjustment[1],
        99,
        0x000A_0000,
        payload_format[0],
        payload_format[1],
    ]);

    let Packet::SignalContext(packet) = parse_packet_exact(&input).expect("valid context") else {
        panic!("expected signal context");
    };

    assert_eq!(packet.prologue.header.tsm, Some(TimestampMode::Coarse));
    assert!(packet.context_changed);
    assert_eq!(packet.reference_point, 100);
    assert_eq!(packet.bandwidth.raw(), 20_000_000_u64 << 20);
    assert_eq!(packet.sample_rate.raw(), 40_000_000_u64 << 20);
    assert_eq!(packet.timestamp_adjustment.raw(), -1234);
    assert_eq!(packet.payload_format.data_item_size_bits, 16);
}

#[test]
fn rejects_context_payload_format_outside_difi_limits() {
    let [cid0, cid1] = class_id(0x0000, 0x0001, 0);
    let bandwidth = fixed_hz(20_000_000);
    let sample_rate = fixed_hz(40_000_000);
    let zero64 = [0, 0];

    let input = bytes(&[
        header(0x4, 0x1, 0x1, 0x2, 0, 27),
        0,
        cid0,
        cid1,
        0,
        0,
        0,
        0x7BB9_8000,
        100,
        bandwidth[0],
        bandwidth[1],
        zero64[0],
        zero64[1],
        zero64[0],
        zero64[1],
        zero64[0],
        zero64[1],
        0,
        0,
        sample_rate[0],
        sample_rate[1],
        zero64[0],
        zero64[1],
        0,
        0,
        0xA000_0000, // bit depth fields imply 1-bit samples, which DIFI forbids
        0,
    ]);

    assert!(matches!(
        parse_packet_exact(&input).unwrap_err(),
        ParseError::InvalidPayloadFormat { .. }
    ));
}

#[test]
fn parses_version_context_and_keeps_packet_class_distinct_from_information_class() {
    let [cid0, cid1] = class_id(0x0001, 0x0004, 0);
    let version_word = (26 << 25) | (130 << 16) | (1 << 10);
    let input = bytes(&[
        header(0x4, 0x1, 0x1, 0x2, 0, 11),
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
    ]);

    let Packet::VersionContext(packet) = parse_packet_exact(&input).expect("valid version") else {
        panic!("expected version context");
    };
    assert_eq!(packet.year, 26);
    assert_eq!(packet.day, 130);
    assert_eq!(packet.revision, 1);

    let [bad_cid0, bad_cid1] = class_id(0x0004, 0x0004, 0);
    let bad = bytes(&[
        header(0x4, 0x1, 0x1, 0x2, 0, 11),
        0,
        bad_cid0,
        bad_cid1,
        0,
        0,
        0,
        0x8000_0002,
        0x0000_000C,
        0x0000_0004,
        version_word,
    ]);
    assert!(matches!(
        parse_packet_exact(&bad).unwrap_err(),
        ParseError::PacketClassNotInInformationClass {
            information_class: difi::InformationClassCode::BasicDataPlaneSampleCount,
            packet_class: PacketClassCode::VersionFlowSignalContext
        }
    ));
}

#[test]
fn parses_timing_flow_control_as_twenty_one_words() {
    let [cid0, cid1] = class_id(0x0002, 0x0005, 0);
    let sample_rate = fixed_hz(40_000_000);
    let timestamp_adjustment = signed_words(250);
    let input = bytes(&[
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
    ]);

    let Packet::TimingFlowControl(packet) = parse_packet_exact(&input).expect("valid flow control")
    else {
        panic!("expected timing flow control");
    };

    assert_eq!(packet.prologue.header.packet_size_words, 21);
    assert_eq!(packet.common.message_id, 7);
    assert_eq!(packet.sample_rate.raw(), 40_000_000_u64 << 20);
    assert_eq!(packet.buffer_size_bytes, 4096);
    assert_eq!(packet.buffer_status.buffer_level, 0x0ABC);
    assert!(packet.buffer_status.overflow);
    assert!(!packet.buffer_status.nearly_full);
    assert!(packet.buffer_status.nearly_empty);
    assert!(!packet.buffer_status.underflow);
}

#[test]
fn parses_sink_capabilities_query_long_and_short_forms() {
    let [cid0, cid1] = class_id(0x0101, 0x0007, 0);
    let long = bytes(&[
        header(0x7, 0, 0x1, 0x2, 0, 13),
        0,
        cid0,
        cid1,
        1,
        0,
        2,
        CAM_EXTENSION_CONTROL_VALIDATE,
        10,
        11,
        12,
        CIF_COMMAND_LONG,
        CIF_CONTROL_FLOW_1,
    ]);
    let Packet::SinkCapabilitiesQuery(packet) =
        parse_packet_exact(&long).expect("valid long query")
    else {
        panic!("expected query");
    };
    assert_eq!(packet.form, CapabilityForm::Long);
    assert_eq!(packet.cif1, Some(CIF_CONTROL_FLOW_1));

    let short = bytes(&[
        header(0x7, 0, 0x1, 0x1, 1, 15),
        0,
        cid0,
        cid1,
        1,
        0,
        2,
        CAM_EXTENSION_CONTROL_VALIDATE,
        10,
        11,
        12,
        CIF_COMMAND_SHORT,
        99,
        0,
        123,
    ]);
    let Packet::SinkCapabilitiesQuery(packet) =
        parse_packet_exact(&short).expect("valid short query")
    else {
        panic!("expected query");
    };
    assert_eq!(packet.form, CapabilityForm::Short);
    assert_eq!(packet.sink_time_calibration_integer, Some(99));
    assert_eq!(packet.sink_time_calibration_fractional, Some(123));
}

#[test]
fn parses_sink_capabilities_response_short_and_borrows_long_capability_table() {
    let [cid0, cid1] = class_id(0x0101, 0x0008, 0);
    let short = bytes(&[
        header(0x7, 0x4, 0x1, 0x2, 0, 18),
        0,
        cid0,
        cid1,
        1,
        0,
        2,
        CAM_EXTENSION_ACK_VALIDATE,
        10,
        11,
        12,
        CIF_COMMAND_SHORT,
        30,
        0,
        31,
        40,
        0,
        41,
    ]);
    let Packet::SinkCapabilitiesResponse(packet) =
        parse_packet_exact(&short).expect("valid short response")
    else {
        panic!("expected response");
    };
    assert_eq!(packet.form, CapabilityForm::Short);
    assert_eq!(packet.control_packet_integer_timestamp, Some(30));
    assert_eq!(packet.sink_reception_fractional_timestamp, Some(41));
    assert!(packet.capability_table.is_empty());

    let long = bytes(&[
        header(0x7, 0x4, 0x1, 0x2, 0, 14),
        0,
        cid0,
        cid1,
        1,
        0,
        2,
        CAM_EXTENSION_ACK_VALIDATE,
        10,
        11,
        12,
        CIF_COMMAND_LONG,
        CIF_CONTROL_FLOW_1,
        0xDEAD_BEEF,
    ]);
    let Packet::SinkCapabilitiesResponse(packet) =
        parse_packet_exact(&long).expect("valid long response")
    else {
        panic!("expected response");
    };
    assert_eq!(packet.form, CapabilityForm::Long);
    assert_eq!(packet.capability_table, &long[52..]);
}

#[test]
fn parses_status_report_forms_with_optional_limits() {
    let [cid0, cid1] = class_id(0x0100, 0x0009, 0);
    let sample_rate = fixed_hz(40_000_000);
    let bandwidth = fixed_hz(20_000_000);
    let input = bytes(&[
        header(0x7, 0, 0x1, 0x2, 0, 21),
        0x0102_0304,
        cid0,
        cid1,
        1,
        0,
        2,
        CAM_CONTROL_EXECUTE,
        10,
        11,
        12,
        0,
        0x0000_0010,
        0x0000_2000,
        0x0000_0008,
        0x0001_0002,
        0x0003_0000,
        sample_rate[0],
        sample_rate[1],
        bandwidth[0],
        bandwidth[1],
    ]);

    let Packet::StatusReport(packet) = parse_packet_exact(&input).expect("valid status") else {
        panic!("expected status report");
    };
    assert_eq!(packet.common.message_id, 10);
    assert_eq!(packet.status_words, [0x10, 0x2000, 0x8]);
    assert!(packet.reference_level_limit.is_some());
    assert_eq!(
        packet.sample_rate_limit.unwrap().raw(),
        40_000_000_u64 << 20
    );
    assert_eq!(packet.bandwidth_limit.unwrap().raw(), 20_000_000_u64 << 20);

    let [standalone_cid0, standalone_cid1] = class_id(0x0101, 0x0009, 0);
    let bad = bytes(&[
        header(0x7, 0, 0x1, 0x2, 0, 15),
        0,
        standalone_cid0,
        standalone_cid1,
        0,
        0,
        0,
        CAM_CONTROL_EXECUTE,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]);
    assert!(matches!(
        parse_packet_exact(&bad).unwrap_err(),
        ParseError::PacketClassNotInInformationClass { .. }
    ));
}
