# DIFI Certification Conformance Hook

This crate does not vendor DIFI Consortium conformance vectors. To run external packet-capture
checks, point `DIFI_CERTIFICATION_DIR` at a local checkout of the official repository or use the
fetch helper:

```sh
pcap-tests/fetch-difi-certification.sh
DIFI_CERTIFICATION_DIR=pcap-tests/DIFI-Certification cargo test --features pcap-tests
```

The `pcap-tests` Cargo feature is intentionally a hook only. Add local tests that read from the
checkout in your environment; keep third-party captures out of this repository unless their
license explicitly permits redistribution.
