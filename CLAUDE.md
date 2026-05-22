# CLAUDE.md

Notes for AI coding agents working on `difi-rs`. End users and contributors should read
[`README.md`](./README.md) for the public API tour and [`CONTEXT.md`](./CONTEXT.md) for the
project glossary; this file exists to give agents a fast orientation without re-deriving the
same facts every session. `AGENTS.md` is a symlink to this file.

## Project

`difi` is a single Rust crate (Cargo edition 2024) that parses UDP payloads containing DIFI
Standard packets. The parser is strict, zero-copy, and `#![forbid(unsafe_code)]`. The default
profile is DIFI 1.3.0 in strict mode; DIFI 1.1 and 1.2.1 are selectable via `ParseOptions`. An
opt-in `write` feature adds a canonical, no-allocation packet writer.

## Commands

- Build (default features): `cargo build`
- Build with writer: `cargo build --features write`
- Test (default features): `cargo test`
- Test broad: `cargo test --all-features` (the `pcap-tests` integration test self-skips unless `DIFI_CERTIFICATION_DIR` is set)
- Lint: `cargo clippy --all-targets --all-features -- -D warnings`
- Format: `cargo fmt --all`
- Bench: `cargo bench`
- Docs: `cargo doc --all-features --open`
- External pcap conformance:

  ```sh
  pcap-tests/fetch-difi-certification.sh
  DIFI_CERTIFICATION_DIR=pcap-tests/DIFI-Certification cargo test --features pcap-tests
  ```

## Source map

- `src/lib.rs` — public API and module registry; `parse_packet`, `parse_packet_exact[_with_options]`, `parse_packet_prefix[_with_options]`.
- `src/parser.rs` — main parse dispatch after prologue validation.
- `src/packet.rs` — `Packet<'a>` enum and `Prologue` struct.
- `src/packet_stream.rs` — `PacketStreamParser` and `ParsedDatagram<'a>` for exact one-datagram parsing plus sequence status.
- `src/header.rs` — `PacketHeader`, `PacketType`, `Tsi`, `Tsf`, `TimestampMode`.
- `src/class_id.rs` — `ClassId` and `DIFI_CID = 0x6A621E`.
- `src/information.rs` — `InformationClassCode`, `PacketClassCode`.
- `src/data.rs` — `SignalDataPacket<'a>` (payload borrowed from input).
- `src/context.rs` — `SignalContextPacket`, fixed-point wrappers `FixedU64` / `FixedI64`.
- `src/command.rs` — `TimingFlowControlPacket`, `SinkCapabilitiesQueryPacket`, `SinkCapabilitiesResponsePacket<'a>`, `StatusReportPacket`, `BufferStatus`, `CapabilityForm`, `CommandCommon`, `ReferenceLevelLimit`.
- `src/version.rs` — `VersionContextPacket`, `DifiVersionCode`.
- `src/standard.rs` — version profile tables, `DifiStandardVersion`, `ParseOptions`, `CompatibilityMode`, `StandardProfile`, `PacketLayout`.
- `src/validation.rs` — shared field-validation helpers.
- `src/payload_format.rs` — `PayloadFormat`, `PayloadSampleFormat`.
- `src/samples.rs` — `ComplexI8`, `ComplexI16`, `iq_i8_samples`, `iq_i16_samples`.
- `src/sequence.rs` — `SequenceTracker`, `SequenceKey`, `SequenceStatus`.
- `src/error.rs` — `ParseError` (thiserror) and `Result<T>` alias.
- `src/raw.rs` — big-endian word/byte read primitives. Use these instead of transmutes.
- `src/writer.rs` — `#[cfg(feature = "write")]` canonical packet encoder; `encoded_len`, `write_packet`, `write_iq_data_i16`, `SignalDataWriteSpec`.

## Tests

Integration tests live in `tests/`:

- `data_packet.rs` — Signal Data parsing.
- `context_version_command.rs` — Context, Version, and Command packets.
- `prologue_and_data.rs` — prologue / header validation.
- `standard_profiles.rs` — per-version packet-type availability rules.
- `helpers.rs` — sample decoder coverage (`iq_i8_samples`, `iq_i16_samples`).
- `packet_stream.rs` — stateful datagram parser and sequence-status coverage.
- `properties.rs` — `proptest`-driven property tests.
- `allocations.rs` — zero-allocation verification on the parse path.
- `writer.rs` — encoder and round-trip tests; requires `--features write`.
- `pcap_certification.rs` — external DIFI Consortium captures; requires `--features pcap-tests` and `DIFI_CERTIFICATION_DIR` set to a checkout.

`benches/parser.rs` is the criterion micro-benchmark suite (`harness = false` in `Cargo.toml`).

## Coding rules

These are enforced by the codebase and should be preserved by any change:

- `#![forbid(unsafe_code)]` at `src/lib.rs:1` is non-negotiable.
- No `transmute`, packed structs, or `repr(C)` parsing tricks — use the big-endian read helpers in `src/raw.rs`.
- All wire reads are big-endian (network byte order).
- The parse path is zero-copy: Signal Data payloads and long-form sink-capability response tables stay as `&[u8]` borrowed from the caller's input.
- The writer never allocates. Callers size the buffer with `encoded_len[_with_options]` first, then write into it. Do not add `Vec`-returning convenience wrappers.
- All fallible parser/writer APIs return `Result<T, ParseError>`. Don't `unwrap` or `panic` on parser inputs.
- Version-specific rules live in `src/standard.rs` as profile-table data, not as ad hoc branches in `src/parser.rs`.

## Feature gates

- `default` (no features) — parser only.
- `write` — canonical packet encoder plus `ComplexI8` / `ComplexI16` IQ Signal Data helpers.
- `serde` — derives serde for copyable metadata types (not payload slices).
- `pcap-tests` — opt-in external conformance smoke test gated on `DIFI_CERTIFICATION_DIR`.

CI-equivalent broad check: `cargo test --all-features`. The `pcap-tests` test self-skips when the env var is unset, so the broad check is safe to run without a local certification checkout.

## Gotchas

- DIFI Consortium conformance captures are not vendored (license). Either run `pcap-tests/fetch-difi-certification.sh` or point `DIFI_CERTIFICATION_DIR` at an existing checkout; `.gitignore` excludes `pcap-tests/DIFI-Certification/`. See `pcap-tests/README.md` for the full ritual.
- `src/lib.rs:2` includes `README.md` as the crate-level rustdoc via `#![doc = include_str!("../README.md")]`, so the README must stay rustdoc-safe (no broken intra-doc links, no headings that confuse `cargo doc`).
- Cargo edition 2024 requires a recent stable Rust toolchain.
- Where the DIFI 1.3.0 prose and tables disagree, the parser follows the field maps. The visible example: Timing Flow Control packets are parsed as 21 words so words 19–21 carry buffer-size and buffer-status fields.
