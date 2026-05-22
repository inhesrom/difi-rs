# Project Context

## Glossary

- Standard Profile: The internal policy object for a DIFI standard version. It decides which packet types, packet classes, information-class memberships, timestamp rules, padding rules, fixed sizes, and CIF/CAM values are valid for that version.
- Wire Syntax: The common bit-level syntax that can be decoded before selecting a version-specific policy, such as packet type nibbles, class ID words, timestamps, and packet sizes.
- Packet Layout: The shared field layout for a typed packet after the prologue has been decoded, such as signal context, version context, timing flow control, or status report.
- Validation Profile: The set of standard-specific checks applied to otherwise shared wire syntax and packet layouts.
- UDP Datagram Payload: The bytes delivered by a UDP receive call after the UDP/IP headers have been removed. In this crate, it is caller-owned input and is expected to contain exactly one complete DIFI packet when passed to the packet stream parser.
- Packet Stream Parser: The transport-agnostic stateful helper that parses one UDP Datagram Payload at a time with exact packet semantics and reports sequence status using an owned `SequenceTracker`.
- Packet Writer: The `write` feature's no-allocation encoder for the current public `Packet<'_>` variants. It emits canonical DIFI words into caller-owned buffers after validating the packet against the selected Standard Profile.
- Canonical Writing: Encoding from decoded packet fields after checking raw/decoded agreement, instead of preserving arbitrary original bytes from contradictory hand-built structs.
- IQ Payload Codec: The narrow ComplexI8 and ComplexI16 Signal Data helpers that write aligned complex signed Cartesian samples directly. They do not implement general DIFI link-efficient packing for arbitrary 4-16 bit sample widths.
