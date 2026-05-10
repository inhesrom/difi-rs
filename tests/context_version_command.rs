mod common;

use difi::{
    CapabilityForm, Packet, PacketClassCode, ParseError, TimestampMode, parse_packet_exact,
};

use common::{
    CAM_CONTROL_EXECUTE, CAM_EXTENSION_ACK_VALIDATE, CAM_EXTENSION_CONTROL_VALIDATE,
    CAM_STATUS_REPORT_EXECUTE, CIF_COMMAND_LONG, CIF_COMMAND_SHORT, CIF_CONTROL_FLOW_0,
    CIF_CONTROL_FLOW_1, bytes, class_id, fixed_hz, header, payload_format, signed_words,
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
    // Word 15 (sink_errors_warnings) low byte must signal both optional limits for a 21-word packet:
    // bit 4 = Reference Level Limit present, bit 3 = Sample Rate & Bandwidth Limits present.
    let sink_errors_warnings = 0x0000_2000 | 0x18;
    let input = bytes(&[
        header(0x7, 0, 0x1, 0x2, 0, 21),
        0x0102_0304,
        cid0,
        cid1,
        1,
        0,
        2,
        CAM_STATUS_REPORT_EXECUTE,
        10,
        11,
        12,
        0,                    // word 12: CIF 0
        0,                    // word 13: CIF 1 (must be 0)
        0x0000_4000,          // word 14: packet_errors (arbitrary bit set for the assertion)
        sink_errors_warnings, // word 15
        0x0001_0002,          // word 16: ref level min/max
        0x0003_0000,          // word 17: ref level resolution + reserved
        sample_rate[0],
        sample_rate[1],
        bandwidth[0],
        bandwidth[1],
    ]);

    let Packet::StatusReport(packet) = parse_packet_exact(&input).expect("valid status") else {
        panic!("expected status report");
    };
    assert_eq!(packet.common.message_id, 10);
    assert_eq!(packet.cif0, 0);
    assert_eq!(packet.cif1, 0);
    assert_eq!(packet.packet_errors, 0x0000_4000);
    assert_eq!(packet.sink_errors_warnings, sink_errors_warnings);
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
        CAM_STATUS_REPORT_EXECUTE,
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

#[test]
fn parses_seventeen_word_status_report_with_reference_level_only() {
    let [cid0, cid1] = class_id(0x0100, 0x0009, 0);
    // 17-word packet: Reference Level Limit present (bit 4 of word 15), no Sample Rate/Bandwidth (bit 3 clear).
    let sink_errors_warnings = 0x0000_8000 | 0x10;
    let input = bytes(&[
        header(0x7, 0, 0x1, 0x2, 0, 17),
        0x0102_0304,
        cid0,
        cid1,
        1,
        0,
        2,
        CAM_STATUS_REPORT_EXECUTE,
        10,
        11,
        12,
        0,
        0,
        0x8000_0000, // packet_errors with bit 31 set ("Selected Packet Type not defined")
        sink_errors_warnings,
        0x0005_FFFB, // ref level max=5 dBm, min=-5 dBm (0xFFFB)
        0x0001_0000, // ref level resolution=1 dB, reserved=0
    ]);

    let Packet::StatusReport(packet) = parse_packet_exact(&input).expect("valid status") else {
        panic!("expected status report");
    };
    assert_eq!(packet.prologue.header.packet_size_words, 17);
    assert_eq!(packet.packet_errors, 0x8000_0000);
    assert_eq!(packet.sink_errors_warnings, sink_errors_warnings);
    let level = packet
        .reference_level_limit
        .expect("ref level limit present");
    assert_eq!(level.raw_min_max, 0x0005_FFFB);
    assert_eq!(level.raw_resolution_reserved, 0x0001_0000);
    assert!(packet.sample_rate_limit.is_none());
    assert!(packet.bandwidth_limit.is_none());
}

#[test]
fn status_report_rejects_flag_bits_inconsistent_with_packet_size() {
    let [cid0, cid1] = class_id(0x0100, 0x0009, 0);
    // 17-word packet but bit 4 is clear in word 15 -> mismatch with declared size.
    let input = bytes(&[
        header(0x7, 0, 0x1, 0x2, 0, 17),
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
        0, // sink_errors_warnings: both flag bits clear, but packet size = 17
        0,
        0,
    ]);
    assert!(matches!(
        parse_packet_exact(&input).unwrap_err(),
        ParseError::InvalidFieldValue {
            field: "status report quantitative flags",
            ..
        }
    ));
}

#[test]
fn status_report_rejects_nonzero_cif1() {
    let [cid0, cid1] = class_id(0x0100, 0x0009, 0);
    let input = bytes(&[
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
        0x0000_0001, // word 13: cif1, must be 0
        0,
        0,
    ]);
    assert!(matches!(
        parse_packet_exact(&input).unwrap_err(),
        ParseError::InvalidFieldValue {
            field: "status report CIF1",
            ..
        }
    ));
}

#[test]
fn signal_context_rejects_non_integer_hz_bandwidth() {
    let [cid0, cid1] = class_id(0x0000, 0x0001, 0);
    let bad_bandwidth = [0x0000_0001_u32, 0x0000_0001_u32]; // low 20 bits non-zero
    let sample_rate = fixed_hz(40_000_000);
    let payload_fmt = payload_format(16);

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
        bad_bandwidth[0],
        bad_bandwidth[1],
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        sample_rate[0],
        sample_rate[1],
        0,
        0,
        0,
        0,
        payload_fmt[0],
        payload_fmt[1],
    ]);

    assert!(matches!(
        parse_packet_exact(&input).unwrap_err(),
        ParseError::FractionalHzNotAllowed {
            field: "context bandwidth",
            ..
        }
    ));
}

#[test]
fn signal_context_rejects_non_integer_hz_frequency_fields() {
    let bandwidth = fixed_hz(20_000_000);
    let sample_rate = fixed_hz(40_000_000);
    let zero64 = [0_u32, 0_u32];
    let payload_fmt = payload_format(16);

    // Helper: build a context packet with `field_word` substituted for one of the 64-bit slots.
    // slot_index: 0 = IF Ref Freq (words 12-13), 1 = RF Ref Freq (14-15), 2 = IF Band Offset (16-17)
    let build = |slot_index: usize, value: [u32; 2]| {
        let [cid0, cid1] = class_id(0x0000, 0x0001, 0);
        let mut slots = [zero64, zero64, zero64];
        slots[slot_index] = value;
        bytes(&[
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
            slots[0][0],
            slots[0][1],
            slots[1][0],
            slots[1][1],
            slots[2][0],
            slots[2][1],
            0,
            0,
            sample_rate[0],
            sample_rate[1],
            0,
            0,
            0,
            0,
            payload_fmt[0],
            payload_fmt[1],
        ])
    };

    let bad_value = [0_u32, 0x0000_0001_u32]; // sub-Hz

    let expectations = [
        (0, "context IF reference frequency"),
        (1, "context RF reference frequency"),
        (2, "context IF band offset"),
    ];
    for (slot, expected_field) in expectations {
        let input = build(slot, bad_value);
        match parse_packet_exact(&input).unwrap_err() {
            ParseError::FractionalHzNotAllowed { field, .. } => {
                assert_eq!(field, expected_field);
            }
            err => panic!("expected FractionalHzNotAllowed for slot {slot}, got {err:?}"),
        }
    }
}
