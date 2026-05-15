# ADR 0001: Strict Canonical Packet Writer

## Status

Accepted

## Context

The parser exposes typed packet structs that contain decoded fields plus some raw words, such as
packet header words, CIF values, CAM values, payload-format words, and status bitfields. A writer
could either preserve original bytes or produce a canonical packet from the decoded model.

Preserving raw bytes would make contradictory hand-built structs ambiguous: the raw header might
declare one packet size while the borrowed payload implies another, or a raw CIF word might disagree
with `context_changed`.

## Decision

The `write` feature provides a strict canonical writer:

- All output is written into caller-owned `&mut [u8]` buffers.
- `encoded_len` and `write_packet` default to strict DIFI 1.3.0.
- `*_with_options` functions reuse the same Standard Profile rules as the parser for DIFI 1.1,
  DIFI 1.2.1, DIFI 1.3.0, and legacy version packet type compatibility.
- The writer validates raw/decoded field agreement before emitting bytes.
- Signal Data IQ helpers support direct ComplexI8 and ComplexI16 sample encoding only.

## Consequences

The writer is allocation-free on valid paths and produces packets that the parser can read back.
It does not provide `Vec` convenience functions.

Raw-byte-preserving reserialization is out of scope. Callers that need exact byte preservation
should retain the original input bytes rather than round-tripping through typed packet structs.

General DIFI link-efficient packing for arbitrary 4-16 bit IQ sample widths is also out of scope.
