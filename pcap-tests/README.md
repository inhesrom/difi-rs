# DIFI Certification Conformance Hook

This crate does not vendor DIFI Consortium conformance vectors. To run external packet-capture
checks, point `DIFI_CERTIFICATION_DIR` at a local checkout of the official repository or use the
fetch helper:

```sh
pcap-tests/fetch-difi-certification.sh
DIFI_CERTIFICATION_DIR=pcap-tests/DIFI-Certification cargo test --features pcap-tests
```

The `pcap-tests` Cargo feature runs a strict smoke test over `.pcapng` captures in
`example_pcaps/`. The test extracts UDP payloads from classic PCAP or PCAPNG files and requires
every UDP payload to be a DIFI packet with CID/OUI `0x6A621E` that parses with a supported
standard profile.

The smoke test is skipped unless `DIFI_CERTIFICATION_DIR` points at a local checkout. Keep
third-party captures out of this repository unless their license explicitly permits redistribution.
