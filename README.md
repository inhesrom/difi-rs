# difi

`difi` is a Rust parser library for UDP payloads containing DIFI Standard packets. The default
parser profile is DIFI 1.3.0 in strict mode.

The parser is intentionally strict and zero-copy:

- `parse_packet_exact(input)` parses one complete packet and rejects trailing bytes.
- `parse_packet_prefix(input)` parses the first packet and returns the remaining bytes.
- `parse_packet(input)` is a documented alias for exact parsing.
- `parse_packet_exact_with_options(input, options)` and
  `parse_packet_prefix_with_options(input, options)` select a specific DIFI standard profile.
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

## Helpers

`SequenceTracker` tracks 4-bit packet sequence numbers independently by packet type, packet
class, and stream ID. It reports `First`, `InOrder`, `Duplicate`, or `Gap`.

The sample helpers are deliberately narrow:

- `iq_i8_samples(payload)` decodes aligned 8-bit complex signed Cartesian samples.
- `iq_i16_samples(payload)` decodes aligned big-endian 16-bit complex signed Cartesian samples.

Other bit depths use DIFI link-efficient packing and are left as borrowed bytes.

## Feature Gates

- Default: parser only.
- `write`: exposes a placeholder writer module. Encoding parsed packets is not implemented yet.
- `serde`: derives serde support for copyable metadata types.
- `pcap-tests`: reserved for local conformance tests against external packet captures.

## External Conformance

Official DIFI conformance assets are not vendored. Use the opt-in hook under `pcap-tests/`:

```sh
pcap-tests/fetch-difi-certification.sh
DIFI_CERTIFICATION_DIR=pcap-tests/DIFI-Certification cargo test --features pcap-tests
```

Keep third-party captures out of this repository unless their license explicitly permits
redistribution.
