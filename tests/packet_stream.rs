mod common;

use difi::{
    CompatibilityMode, DifiStandardVersion, Packet, PacketStreamParser, PacketType, ParseError,
    ParseOptions, SequenceStatus,
};

use common::{bytes, class_id, header};

const PROLOGUE_BYTES: usize = 7 * 4;

fn signal_data_packet(sequence: u8) -> Vec<u8> {
    let [cid0, cid1] = class_id(0x0000, 0x0000, 0);
    bytes(&[
        header(0x1, 0, 0x1, 0x2, sequence, 8),
        0x0102_0304,
        cid0,
        cid1,
        7,
        0,
        42,
        0xABCD_EF01,
    ])
}

fn v1_1_version_context_packet() -> Vec<u8> {
    let [cid0, cid1] = class_id(0x0001, 0x0004, 0);
    let version_word = (26 << 25) | (130 << 16) | (1 << 10);

    bytes(&[
        header(0x5, 0x1, 0x1, 0x2, 0, 11),
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

fn v1_1_options() -> ParseOptions {
    ParseOptions {
        standard: DifiStandardVersion::V1_1,
        compatibility: CompatibilityMode::Strict,
    }
}

#[test]
fn packet_stream_parser_reports_sequence_status_across_datagrams() {
    let first = signal_data_packet(3);
    let second = signal_data_packet(4);
    let duplicate = signal_data_packet(4);
    let gap = signal_data_packet(6);
    let mut parser = PacketStreamParser::new();

    assert_eq!(
        parser
            .parse_datagram(&first)
            .expect("valid first datagram")
            .sequence_status,
        SequenceStatus::First
    );
    assert_eq!(
        parser
            .parse_datagram(&second)
            .expect("valid second datagram")
            .sequence_status,
        SequenceStatus::InOrder
    );
    assert_eq!(
        parser
            .parse_datagram(&duplicate)
            .expect("valid duplicate datagram")
            .sequence_status,
        SequenceStatus::Duplicate
    );
    assert_eq!(
        parser
            .parse_datagram(&gap)
            .expect("valid gap datagram")
            .sequence_status,
        SequenceStatus::Gap {
            expected: 5,
            actual: 6
        }
    );
}

#[test]
fn packet_stream_parser_rejects_concatenated_packets() {
    let first = signal_data_packet(0);
    let second = signal_data_packet(1);
    let mut jumbo = first.clone();
    jumbo.extend_from_slice(&second);
    let mut parser = PacketStreamParser::new();

    assert_eq!(
        parser.parse_datagram(&jumbo).unwrap_err(),
        ParseError::TrailingBytes {
            trailing: second.len()
        }
    );
}

#[test]
fn packet_stream_parser_preserves_borrowed_signal_data_payload() {
    let input = signal_data_packet(7);
    let mut parser = PacketStreamParser::new();
    let parsed = parser.parse_datagram(&input).expect("valid data datagram");
    let Packet::SignalData(packet) = parsed.packet else {
        panic!("expected signal data packet");
    };

    let expected_payload = &input[PROLOGUE_BYTES..];
    assert_eq!(packet.payload, expected_payload);
    assert_eq!(packet.payload.as_ptr(), expected_payload.as_ptr());
}

#[test]
fn packet_stream_parser_with_options_applies_standard_profile() {
    let input = v1_1_version_context_packet();
    let mut default_parser = PacketStreamParser::new();
    let mut v1_1_parser = PacketStreamParser::with_options(v1_1_options());

    assert!(matches!(
        default_parser.parse_datagram(&input).unwrap_err(),
        ParseError::PacketTypeNotAvailableInStandard {
            standard: DifiStandardVersion::V1_3_0,
            packet_type: PacketType::VersionWithStreamId
        }
    ));

    let parsed = v1_1_parser
        .parse_datagram(&input)
        .expect("valid DIFI 1.1 version context packet");
    assert_eq!(parsed.sequence_status, SequenceStatus::First);
    assert!(matches!(parsed.packet, Packet::VersionContext(_)));
}

#[test]
fn packet_stream_parser_can_reset_sequences() {
    let first = signal_data_packet(3);
    let second = signal_data_packet(4);
    let mut parser = PacketStreamParser::new();

    assert_eq!(
        parser
            .parse_datagram(&first)
            .expect("valid first datagram")
            .sequence_status,
        SequenceStatus::First
    );
    assert_eq!(
        parser
            .parse_datagram(&second)
            .expect("valid second datagram")
            .sequence_status,
        SequenceStatus::InOrder
    );

    parser.reset_sequences();

    assert_eq!(
        parser
            .parse_datagram(&second)
            .expect("valid datagram after reset")
            .sequence_status,
        SequenceStatus::First
    );
}
