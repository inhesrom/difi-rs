mod common;

use difi::{
    Packet, PacketClassCode, ParseError, SequenceStatus, SequenceTracker, parse_packet_prefix,
};
use proptest::prelude::*;

use common::{bytes, class_id, header};

proptest! {
    #[test]
    fn arbitrary_input_never_panics(input in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_packet_prefix(&input);
    }

    #[test]
    fn declared_packet_size_larger_than_input_reports_truncation(words in 8u16..128) {
        let [cid0, cid1] = class_id(0x0000, 0x0000, 0);
        let input = bytes(&[
            header(0x1, 0, 0x1, 0x2, 0, words),
            0,
            cid0,
            cid1,
            0,
            0,
            0,
        ]);

        prop_assert_eq!(
            parse_packet_prefix(&input).unwrap_err(),
            ParseError::PacketTruncated {
                needed: words as usize * 4,
                actual: 28
            }
        );
    }

    #[test]
    fn valid_signal_data_header_and_class_round_trip(seq in 0u8..16, stream_id in any::<u32>(), payload in any::<u32>()) {
        let [cid0, cid1] = class_id(0x0000, 0x0000, 0);
        let input = bytes(&[
            header(0x1, 0, 0x1, 0x2, seq, 8),
            stream_id,
            cid0,
            cid1,
            1,
            0,
            2,
            payload,
        ]);

        let Packet::SignalData(packet) = difi::parse_packet_exact(&input).expect("valid data") else {
            panic!("expected data");
        };
        prop_assert_eq!(packet.prologue.header.sequence, seq);
        prop_assert_eq!(packet.prologue.stream_id, stream_id);
        prop_assert_eq!(packet.prologue.class_id.packet_class, PacketClassCode::StandardFlowSignalData);
        prop_assert_eq!(packet.payload, &input[28..]);
    }

    #[test]
    fn class_identifier_reserved_bits_fail(bits in 1u32..8) {
        let [_, cid1] = class_id(0x0000, 0x0000, 0);
        let input = bytes(&[
            header(0x1, 0, 0x1, 0x2, 0, 8),
            0,
            (bits << 24) | 0x006A_621E,
            cid1,
            0,
            0,
            0,
            0,
        ]);

        let err = difi::parse_packet_exact(&input).unwrap_err();
        let is_reserved_error = matches!(
            err,
            ParseError::ReservedBitsNonZero {
                field: "class identifier",
                ..
            }
        );
        prop_assert!(is_reserved_error);
    }

    #[test]
    fn sequence_tracker_wraparound_is_in_order(start in 0u8..16) {
        let mut tracker = SequenceTracker::new();
        let next = (start + 1) & 0x0F;

        prop_assert_eq!(
            tracker.observe_fields(
                difi::PacketType::SignalDataWithStreamId,
                PacketClassCode::StandardFlowSignalData,
                0xCAFE_BABE,
                start
            ),
            SequenceStatus::First
        );
        prop_assert_eq!(
            tracker.observe_fields(
                difi::PacketType::SignalDataWithStreamId,
                PacketClassCode::StandardFlowSignalData,
                0xCAFE_BABE,
                next
            ),
            SequenceStatus::InOrder
        );
    }
}
