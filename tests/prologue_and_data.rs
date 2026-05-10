mod common;

use difi::{
    InformationClassCode, Packet, PacketClassCode, ParseError, Tsf, parse_packet_exact,
    parse_packet_prefix,
};

use common::{bytes, class_id, header};

fn standard_data_words(size_words: u16, seq: u8) -> Vec<u32> {
    let [cid0, cid1] = class_id(0x0000, 0x0000, 0);
    vec![
        header(0x1, 0, 0x1, 0x2, seq, size_words),
        0x0102_0304,
        cid0,
        cid1,
        7,
        0,
        42,
        0x0102_0304,
    ]
}

#[test]
fn prefix_parser_consumes_one_packet_and_returns_remainder() {
    let first = bytes(&standard_data_words(8, 3));
    let second = bytes(&standard_data_words(8, 4));
    let mut input = first.clone();
    input.extend_from_slice(&second);

    let (packet, remainder) = parse_packet_prefix(&input).expect("valid first packet");
    assert_eq!(packet.prologue().header.sequence, 3);
    assert_eq!(remainder, second.as_slice());
}

#[test]
fn exact_parser_rejects_trailing_bytes() {
    let mut input = bytes(&standard_data_words(8, 0));
    input.push(0xAA);

    assert_eq!(
        parse_packet_exact(&input).unwrap_err(),
        ParseError::TrailingBytes { trailing: 1 }
    );
}

#[test]
fn rejects_truncated_packet_size() {
    let mut input = bytes(&standard_data_words(9, 0));
    input.truncate(32);

    assert_eq!(
        parse_packet_exact(&input).unwrap_err(),
        ParseError::PacketTruncated {
            needed: 36,
            actual: 32
        }
    );
}

#[test]
fn rejects_missing_class_id_indicator_before_reading_class_id() {
    let mut words = standard_data_words(8, 0);
    words[0] &= !(1 << 27);

    assert_eq!(
        parse_packet_exact(&bytes(&words)).unwrap_err(),
        ParseError::MissingClassId
    );
}

#[test]
fn rejects_invalid_difi_cid() {
    let mut words = standard_data_words(8, 0);
    words[2] = 0x006A_621F;

    assert_eq!(
        parse_packet_exact(&bytes(&words)).unwrap_err(),
        ParseError::InvalidOui { actual: 0x6A_621F }
    );
}

#[test]
fn rejects_unknown_packet_type_and_reserved_timestamps() {
    let mut words = standard_data_words(8, 0);
    words[0] = header(0x2, 0, 0x1, 0x2, 0, 8);
    assert!(matches!(
        parse_packet_exact(&bytes(&words)).unwrap_err(),
        ParseError::UnsupportedPacketType { value: 0x2 }
    ));

    words = standard_data_words(8, 0);
    words[0] = header(0x1, 0, 0x0, 0x2, 0, 8);
    assert_eq!(
        parse_packet_exact(&bytes(&words)).unwrap_err(),
        ParseError::InvalidTsi { value: 0 }
    );

    words = standard_data_words(8, 0);
    words[0] = header(0x1, 0, 0x1, 0x3, 0, 8);
    assert_eq!(
        parse_packet_exact(&bytes(&words)).unwrap_err(),
        ParseError::InvalidTsf { value: 3 }
    );
}

#[test]
fn sample_count_data_allows_zeroed_padding_when_information_class_permits_it() {
    let [cid0, cid1] = class_id(0x0002, 0x0002, 12);
    let input = bytes(&[
        header(0x1, 0, 0x1, 0x1, 0, 8),
        0x0102_0304,
        cid0,
        cid1,
        0,
        0,
        1,
        0xABCD_0000,
    ]);

    let Packet::SignalData(packet) = parse_packet_exact(&input).expect("valid padded data") else {
        panic!("expected data");
    };
    assert_eq!(packet.prologue.header.tsf, Tsf::SampleCount);
    assert_eq!(
        packet.prologue.class_id.information_class,
        InformationClassCode::DataPlaneUpstreamFlowControlSampleCount
    );
}

#[test]
fn sample_count_data_rejects_nonzero_padding_bits() {
    let [cid0, cid1] = class_id(0x0002, 0x0002, 12);
    let input = bytes(&[
        header(0x1, 0, 0x1, 0x1, 0, 8),
        0x0102_0304,
        cid0,
        cid1,
        0,
        0,
        1,
        0xABCD_0001,
    ]);

    assert_eq!(
        parse_packet_exact(&input).unwrap_err(),
        ParseError::NonZeroPaddingBits
    );
}

#[test]
fn basic_data_plane_rejects_nonzero_pad_bit_count() {
    let [cid0, cid1] = class_id(0x0000, 0x0000, 1);
    let input = bytes(&[
        header(0x1, 0, 0x1, 0x2, 0, 8),
        0x0102_0304,
        cid0,
        cid1,
        0,
        0,
        1,
        0,
    ]);

    assert_eq!(
        parse_packet_exact(&input).unwrap_err(),
        ParseError::PadBitsNotAllowed {
            information_class: InformationClassCode::BasicDataPlane,
            packet_class: PacketClassCode::StandardFlowSignalData,
            pad_bit_count: 1
        }
    );
}

#[test]
fn rejects_packet_class_with_wrong_tsf() {
    let mut words = standard_data_words(8, 0);
    words[0] = header(0x1, 0, 0x1, 0x1, 0, 8);

    assert_eq!(
        parse_packet_exact(&bytes(&words)).unwrap_err(),
        ParseError::InvalidTsfForPacketClass {
            packet_class: PacketClassCode::StandardFlowSignalData,
            expected: Tsf::RealTimePicoseconds,
            actual: Tsf::SampleCount
        }
    );
}
