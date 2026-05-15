#![cfg(feature = "write")]

mod common;

use difi::writer::{
    SignalDataWriteSpec, WriteError, WriteOptions, encoded_iq_data_i8_len, encoded_iq_data_i16_len,
    encoded_len, encoded_len_with_options, write_iq_data_i8, write_iq_data_i16, write_packet,
    write_packet_with_options,
};
use difi::{
    CompatibilityMode, ComplexI8, ComplexI16, DifiStandardVersion, InformationClassCode, Packet,
    PacketClassCode, PacketType, ParseError, ParseOptions, SignalDataPacket, Tsf, Tsi,
    parse_packet_exact, parse_packet_exact_with_options,
};

use common::{
    CAM_CONTROL_EXECUTE, CAM_EXTENSION_ACK_VALIDATE, CAM_EXTENSION_CONTROL_VALIDATE,
    CAM_STATUS_REPORT_EXECUTE, CIF_COMMAND_LONG, CIF_COMMAND_SHORT, CIF_CONTROL_FLOW_0,
    CIF_CONTROL_FLOW_1, bytes, class_id, fixed_hz, header, payload_format, signed_words,
};

fn assert_write_round_trips(input: &[u8]) {
    let packet = parse_packet_exact(input).expect("valid fixture");
    assert_eq!(encoded_len(&packet).expect("encoded length"), input.len());

    let mut out = vec![0_u8; input.len()];
    let written = write_packet(&packet, &mut out).expect("write succeeds");
    assert_eq!(written, input.len());
    assert_eq!(out.as_slice(), input);
}

fn standard_data() -> Vec<u8> {
    let [cid0, cid1] = class_id(0x0000, 0x0000, 0);
    bytes(&[
        header(0x1, 0, 0x1, 0x2, 3, 9),
        0x0102_0304,
        cid0,
        cid1,
        7,
        0,
        42,
        0x0102_0304,
        0x0506_0708,
    ])
}

fn options(standard: DifiStandardVersion, compatibility: CompatibilityMode) -> WriteOptions {
    WriteOptions {
        standard,
        compatibility,
    }
}

fn parse_options(options: WriteOptions) -> ParseOptions {
    ParseOptions {
        standard: options.standard,
        compatibility: options.compatibility,
    }
}

fn strict(standard: DifiStandardVersion) -> WriteOptions {
    options(standard, CompatibilityMode::Strict)
}

#[test]
fn writes_standard_signal_data_fixture() {
    let input = standard_data();
    let packet = parse_packet_exact(&input).expect("valid data");
    assert!(matches!(packet, Packet::SignalData(_)));

    assert_eq!(encoded_len(&packet).expect("encoded length"), input.len());

    let mut too_small = [0_u8; 35];
    assert!(matches!(
        write_packet(&packet, &mut too_small),
        Err(WriteError::OutputTooSmall {
            needed: 36,
            actual: 35
        })
    ));

    let mut out = [0_u8; 36];
    let written = write_packet(&packet, &mut out).expect("write succeeds");
    assert_eq!(written, input.len());
    assert_eq!(&out[..written], input.as_slice());
}

#[test]
fn writes_signal_and_version_context_fixtures() {
    let [signal_cid0, signal_cid1] = class_id(0x0000, 0x0001, 0);
    let bandwidth = fixed_hz(20_000_000);
    let if_ref = signed_words(0);
    let rf_ref = signed_words(1_500_000_000_i64 << 20);
    let if_offset = signed_words(-2_000_000_i64 << 20);
    let sample_rate = fixed_hz(40_000_000);
    let timestamp_adjustment = signed_words(-1234);
    let payload_format = payload_format(16);
    let signal_context = bytes(&[
        header(0x4, 0x1, 0x1, 0x2, 2, 27),
        0x0102_0304,
        signal_cid0,
        signal_cid1,
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
    assert_write_round_trips(&signal_context);

    let [version_cid0, version_cid1] = class_id(0x0001, 0x0004, 0);
    let version_word = (26 << 25) | (130 << 16) | (1 << 10);
    let version_context = bytes(&[
        header(0x4, 0x1, 0x1, 0x2, 0, 11),
        0xCAFE_BABE,
        version_cid0,
        version_cid1,
        1,
        0,
        2,
        0x8000_0002,
        0x0000_000C,
        0x0000_0004,
        version_word,
    ]);
    assert_write_round_trips(&version_context);
}

#[test]
fn rejects_raw_decoded_field_disagreement() {
    let [signal_cid0, signal_cid1] = class_id(0x0000, 0x0001, 0);
    let bandwidth = fixed_hz(20_000_000);
    let sample_rate = fixed_hz(40_000_000);
    let payload_format = payload_format(16);
    let input = bytes(&[
        header(0x4, 0x1, 0x1, 0x2, 2, 27),
        0x0102_0304,
        signal_cid0,
        signal_cid1,
        123,
        0,
        456,
        0xFBB9_8000,
        100,
        bandwidth[0],
        bandwidth[1],
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
        99,
        0x000A_0000,
        payload_format[0],
        payload_format[1],
    ]);
    let Packet::SignalContext(mut packet) = parse_packet_exact(&input).expect("valid context")
    else {
        panic!("expected signal context");
    };
    packet.context_changed = false;

    assert!(matches!(
        encoded_len(&Packet::SignalContext(packet)),
        Err(WriteError::FieldMismatch {
            field: "signal_context.cif0",
            expected: 0x7BB9_8000,
            actual: 0xFBB9_8000
        })
    ));
}

#[test]
fn writes_command_and_link_establishment_fixtures() {
    let [timing_cid0, timing_cid1] = class_id(0x0002, 0x0005, 0);
    let sample_rate = fixed_hz(40_000_000);
    let timestamp_adjustment = signed_words(250);
    let timing_flow_control = bytes(&[
        header(0x6, 0, 0x1, 0x1, 0, 21),
        0x0102_0304,
        timing_cid0,
        timing_cid1,
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
    assert_write_round_trips(&timing_flow_control);

    let [link_cid0, link_cid1] = class_id(0x0101, 0x0007, 0);
    let query_long = bytes(&[
        header(0x7, 0, 0x1, 0x2, 0, 13),
        0,
        link_cid0,
        link_cid1,
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
    assert_write_round_trips(&query_long);

    let query_short = bytes(&[
        header(0x7, 0, 0x1, 0x1, 1, 15),
        0,
        link_cid0,
        link_cid1,
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
    assert_write_round_trips(&query_short);

    let [response_cid0, response_cid1] = class_id(0x0101, 0x0008, 0);
    let response_short = bytes(&[
        header(0x7, 0x4, 0x1, 0x2, 0, 18),
        0,
        response_cid0,
        response_cid1,
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
    assert_write_round_trips(&response_short);

    let response_long = bytes(&[
        header(0x7, 0x4, 0x1, 0x2, 0, 14),
        0,
        response_cid0,
        response_cid1,
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
    assert_write_round_trips(&response_long);
}

#[test]
fn writes_status_report_word_forms() {
    let [cid0, cid1] = class_id(0x0100, 0x0009, 0);
    let minimal = bytes(&[
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
    ]);
    assert_write_round_trips(&minimal);

    let reference_only = bytes(&[
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
        0x8000_0000,
        0x0000_8010,
        0x0005_FFFB,
        0x0001_0000,
    ]);
    assert_write_round_trips(&reference_only);

    let sample_rate = fixed_hz(40_000_000);
    let bandwidth = fixed_hz(20_000_000);
    let full = bytes(&[
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
        0,
        0,
        0x0000_4000,
        0x0000_2018,
        0x0001_0002,
        0x0003_0000,
        sample_rate[0],
        sample_rate[1],
        bandwidth[0],
        bandwidth[1],
    ]);
    assert_write_round_trips(&full);
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

#[test]
fn write_options_match_parser_standard_profiles() {
    let v1_3_version = version_context(0x4);
    assert_write_round_trips(&v1_3_version);

    let v1_1_options = strict(DifiStandardVersion::V1_1);
    let v1_1_version = version_context(0x5);
    let v1_1_packet = parse_packet_exact_with_options(&v1_1_version, parse_options(v1_1_options))
        .expect("valid v1.1 version");
    let mut out = [0_u8; 44];
    assert_eq!(
        write_packet_with_options(&v1_1_packet, &mut out, v1_1_options).expect("write v1.1"),
        v1_1_version.len()
    );
    assert_eq!(&out, v1_1_version.as_slice());

    assert!(matches!(
        encoded_len(&v1_1_packet),
        Err(WriteError::Profile {
            source: ParseError::PacketTypeNotAvailableInStandard {
                standard: DifiStandardVersion::V1_3_0,
                packet_type: PacketType::VersionWithStreamId
            }
        })
    ));

    let v1_3_packet = parse_packet_exact(&v1_3_version).expect("valid v1.3 version");
    assert!(matches!(
        encoded_len_with_options(&v1_3_packet, v1_1_options),
        Err(WriteError::Profile {
            source: ParseError::PacketTypeClassMismatch {
                packet_type: PacketType::ContextWithStreamId,
                packet_class: PacketClassCode::VersionFlowSignalContext
            }
        })
    ));

    let v1_2_strict = strict(DifiStandardVersion::V1_2_1);
    assert!(encoded_len_with_options(&v1_3_packet, v1_2_strict).is_ok());
    assert!(matches!(
        encoded_len_with_options(&v1_1_packet, v1_2_strict),
        Err(WriteError::Profile {
            source: ParseError::PacketTypeNotAvailableInStandard {
                standard: DifiStandardVersion::V1_2_1,
                packet_type: PacketType::VersionWithStreamId
            }
        })
    ));
    assert!(
        encoded_len_with_options(
            &v1_1_packet,
            options(
                DifiStandardVersion::V1_2_1,
                CompatibilityMode::LegacyVersionPacketType
            ),
        )
        .is_ok()
    );
}

#[test]
fn write_options_reject_packets_outside_selected_standard() {
    let sample_count_data = {
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
    };
    let sample_count_packet = parse_packet_exact(&sample_count_data).expect("valid v1.3 data");
    assert!(matches!(
        encoded_len_with_options(&sample_count_packet, strict(DifiStandardVersion::V1_1)),
        Err(WriteError::Profile {
            source: ParseError::PacketClassNotAvailableInStandard {
                standard: DifiStandardVersion::V1_1,
                packet_class: PacketClassCode::SampleCountSignalData
            }
        })
    ));

    let [cid0, cid1] = class_id(0x0100, 0x0009, 0);
    let status_report = bytes(&[
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
    ]);
    let status_packet = parse_packet_exact(&status_report).expect("valid v1.3 status");
    assert!(matches!(
        encoded_len_with_options(&status_packet, strict(DifiStandardVersion::V1_2_1)),
        Err(WriteError::Profile {
            source: ParseError::PacketTypeNotAvailableInStandard {
                standard: DifiStandardVersion::V1_2_1,
                packet_type: PacketType::ExtensionCommandWithStreamId
            }
        })
    ));
}

#[test]
fn checked_encoded_len_rejects_non_word_aligned_signal_data_payload() {
    let payload = [0xAA_u8, 0xBB];
    let valid = standard_data();
    let Packet::SignalData(parsed) = parse_packet_exact(&valid).expect("valid fixture") else {
        panic!("expected signal data");
    };
    let packet = Packet::SignalData(SignalDataPacket {
        prologue: parsed.prologue,
        payload: &payload,
    });

    assert!(matches!(
        encoded_len(&packet),
        Err(WriteError::PayloadLengthNotWordAligned { len: 2 })
    ));
}

fn iq_spec() -> SignalDataWriteSpec {
    SignalDataWriteSpec {
        stream_id: 0x0102_0304,
        information_class: InformationClassCode::BasicDataPlane,
        packet_class: PacketClassCode::StandardFlowSignalData,
        tsi: Tsi::Utc,
        tsf: Tsf::RealTimePicoseconds,
        sequence: 5,
        integer_seconds_timestamp: 7,
        fractional_seconds_timestamp: 42,
    }
}

#[test]
fn writes_direct_complex_i8_iq_data() {
    let samples = [ComplexI8 { i: 1, q: -1 }, ComplexI8 { i: -128, q: 127 }];
    let [cid0, cid1] = class_id(0x0000, 0x0000, 0);
    let expected = bytes(&[
        header(0x1, 0, 0x1, 0x2, 5, 8),
        0x0102_0304,
        cid0,
        cid1,
        7,
        0,
        42,
        0x01FF_807F,
    ]);

    assert_eq!(
        encoded_iq_data_i8_len(iq_spec(), &samples).expect("len"),
        expected.len()
    );
    let mut out = [0_u8; 32];
    let written = write_iq_data_i8(iq_spec(), &samples, &mut out).expect("write");
    assert_eq!(written, expected.len());
    assert_eq!(&out, expected.as_slice());

    let odd = [ComplexI8 { i: 1, q: 2 }];
    assert!(matches!(
        encoded_iq_data_i8_len(iq_spec(), &odd),
        Err(WriteError::OddComplexI8SampleCount { samples: 1 })
    ));
}

#[test]
fn writes_direct_complex_i16_iq_data() {
    let samples = [
        ComplexI16 { i: 1, q: -2 },
        ComplexI16 {
            i: -32768,
            q: 32767,
        },
    ];
    let [cid0, cid1] = class_id(0x0000, 0x0000, 0);
    let expected = bytes(&[
        header(0x1, 0, 0x1, 0x2, 5, 9),
        0x0102_0304,
        cid0,
        cid1,
        7,
        0,
        42,
        0x0001_FFFE,
        0x8000_7FFF,
    ]);

    assert_eq!(
        encoded_iq_data_i16_len(iq_spec(), &samples).expect("len"),
        expected.len()
    );
    let mut out = [0_u8; 36];
    let written = write_iq_data_i16(iq_spec(), &samples, &mut out).expect("write");
    assert_eq!(written, expected.len());
    assert_eq!(&out, expected.as_slice());
}
