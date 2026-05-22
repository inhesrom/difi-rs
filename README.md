# difi

`difi` is a Rust parser library for UDP payloads containing DIFI Standard packets, with an
optional buffer-only writer behind the `write` feature. The default parser and writer profile is
DIFI 1.3.0 in strict mode.

The parser is intentionally strict and zero-copy:

- `parse_packet_exact(input)` parses one complete packet and rejects trailing bytes.
- `parse_packet_prefix(input)` parses the first packet and returns the remaining bytes.
- `parse_packet(input)` is a documented alias for exact parsing.
- `parse_packet_exact_with_options(input, options)` and
  `parse_packet_prefix_with_options(input, options)` select a specific DIFI standard profile.
- `PacketStreamParser` parses one UDP datagram payload at a time with exact packet semantics and
  reports sequence status.
- Signal-data payloads and long-form sink-capability response extension tables are returned as
  borrowed `&[u8]` slices into the caller's input buffer.
- The crate forbids unsafe code and uses explicit big-endian reads rather than packed structs or
  transmutes.

## Supported Packet Classes

The public `Packet<'a>` enum exposes typed variants for:

- Standard and sample-count Signal Data packets (`0x0000`, `0x0002`)
- Standard and sample-count Signal Context packets (`0x0001`, `0x0003`)
- Version Context packets (`0x0004`)
- Sample-count and real-time Timing Flow Control packets (`0x0005`, `0x0006`)
- Sink Capabilities Query packets (`0x0007`)
- Sink Capabilities Response packets (`0x0008`)
- Status Report packets (`0x0009`)

Packet type, TSI, TSF, TSM, information-class, packet-class, capability-form, sequence-status,
and payload-format fields are represented with typed enums. Context and control metadata keeps
raw fixed-point values in typed wrappers such as `FixedU64` and `FixedI64`; callers decide when
and how to convert units.

## Validation

Parsing validates the DIFI prologue before dispatch: packet size, class ID indicator, DIFI CID
`0x6A621E`, reserved bits, TSI/TSF legality, packet type/class pairing, information-class
membership, padding permissions, fixed packet sizes, required CIF/CAM values where specified by
the supported layouts, and exact/prefix length semantics.

The implementation follows the field maps in the DIFI 1.3.0 PDF where prose conflicts with
tables. In particular, Timing Flow Control packets are parsed as 21-word packets so words 19-21
carry the buffer-size and buffer-status fields.

`ParseOptions` selects `DifiStandardVersion::V1_1`, `V1_2_1`, or `V1_3_0`. Older profiles reject
packet classes added by later standards. `CompatibilityMode::LegacyVersionPacketType` allows DIFI
1.2.1 parsing to accept the DIFI 1.1 version-context packet type `0x5`; strict DIFI 1.2.1 and the
default DIFI 1.3.0 profile use context packet type `0x4` for version context.

## Datagram Streams

`PacketStreamParser` is a transport-agnostic helper for real-time UDP consumers. Each call parses
one UDP datagram payload with `parse_packet_exact_with_options`, so trailing bytes and concatenated
DIFI packets are rejected. The parser also owns a `SequenceTracker` and returns `First`, `InOrder`,
`Duplicate`, or `Gap` for each accepted datagram.

Create one parser per source or source group when stream IDs can overlap:

```rust,ignore
use std::net::UdpSocket;

use difi::{Packet, PacketStreamParser, SequenceStatus};

let socket = UdpSocket::bind("0.0.0.0:4991")?;
let mut parser = PacketStreamParser::new();
let mut buffer = [0_u8; 9000];

loop {
    let (len, source) = socket.recv_from(&mut buffer)?;
    let parsed = parser.parse_datagram(&buffer[..len])?;

    match parsed.sequence_status {
        SequenceStatus::First | SequenceStatus::InOrder => {}
        SequenceStatus::Duplicate => eprintln!("duplicate DIFI sequence from {source}"),
        SequenceStatus::Gap { expected, actual } => {
            eprintln!("DIFI sequence gap from {source}: expected {expected}, got {actual}");
        }
    }

    if let Packet::SignalData(packet) = parsed.packet {
        let payload = packet.payload;
        // `payload` is borrowed from `buffer` and must not outlive this receive iteration.
        println!("stream=0x{:08X} payload_bytes={}", packet.prologue.stream_id, payload.len());
    }
}
```

## Helpers

`SequenceTracker` tracks 4-bit packet sequence numbers independently by packet type, packet
class, and stream ID. It reports `First`, `InOrder`, `Duplicate`, or `Gap`.

The sample helpers are deliberately narrow:

- `iq_i8_samples(payload)` decodes aligned 8-bit complex signed Cartesian samples.
- `iq_i16_samples(payload)` decodes aligned big-endian 16-bit complex signed Cartesian samples.

Other bit depths use DIFI link-efficient packing and are left as borrowed bytes.

## Writing

Enable the `write` feature to encode the current public `Packet<'_>` variants into caller-owned
buffers:

- `writer::encoded_len(packet)` and `writer::write_packet(packet, out)` use strict DIFI 1.3.0.
- `writer::encoded_len_with_options` and `writer::write_packet_with_options` select DIFI 1.1,
  DIFI 1.2.1, or legacy version packet type compatibility.
- The writer validates raw/decoded field agreement, standard-profile rules, packet sizes, padding,
  fixed CIF/CAM values, and output capacity before writing.
- Output is canonical and parseable. It is not a raw-byte-preserving reserializer for contradictory
  hand-built packet structs.

The writer never allocates and does not provide `Vec` convenience functions. Size the output buffer
first, then write into it:

```rust,ignore
let packet = difi::parse_packet_exact(input)?;
let len = difi::writer::encoded_len(&packet)?;
let mut out = [0_u8; 1500];
let written = difi::writer::write_packet(&packet, &mut out[..len])?;
assert_eq!(written, len);
```

For common IQ Signal Data payloads, direct helpers avoid building a `Packet<'_>`:

```rust,ignore
let spec = difi::writer::SignalDataWriteSpec {
    stream_id: 0x0102_0304,
    information_class: difi::InformationClassCode::BasicDataPlane,
    packet_class: difi::PacketClassCode::StandardFlowSignalData,
    tsi: difi::Tsi::Utc,
    tsf: difi::Tsf::RealTimePicoseconds,
    sequence: 0,
    integer_seconds_timestamp: 7,
    fractional_seconds_timestamp: 42,
};
let samples = [difi::ComplexI16 { i: 1, q: -2 }];
let mut out = [0_u8; 64];
let written = difi::writer::write_iq_data_i16(spec, &samples, &mut out)?;
```

## Feature Gates

- Default: parser only.
- `write`: exposes strict canonical packet writing and direct ComplexI8/ComplexI16 IQ Signal Data
  helpers.
- `serde`: derives serde support for copyable metadata types.
- `pcap-tests`: enables opt-in smoke tests against external DIFI certification captures.

## External Conformance

Official DIFI conformance assets are not vendored. Use the opt-in hook under `pcap-tests/` to
clone or update a local checkout and parse known DIFI UDP payloads from its example captures:

```sh
pcap-tests/fetch-difi-certification.sh
DIFI_CERTIFICATION_DIR=pcap-tests/DIFI-Certification cargo test --features pcap-tests
```

The `pcap-tests` feature skips this external smoke test unless `DIFI_CERTIFICATION_DIR` points at a
local checkout. Keep third-party captures out of this repository unless their license explicitly
permits redistribution.
