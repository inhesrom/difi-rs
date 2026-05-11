# Project Context

## Glossary

- Standard Profile: The internal policy object for a DIFI standard version. It decides which packet types, packet classes, information-class memberships, timestamp rules, padding rules, fixed sizes, and CIF/CAM values are valid for that version.
- Wire Syntax: The common bit-level syntax that can be decoded before selecting a version-specific policy, such as packet type nibbles, class ID words, timestamps, and packet sizes.
- Packet Layout: The shared field layout for a typed packet after the prologue has been decoded, such as signal context, version context, timing flow control, or status report.
- Validation Profile: The set of standard-specific checks applied to otherwise shared wire syntax and packet layouts.
