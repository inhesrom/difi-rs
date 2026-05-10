#!/usr/bin/env sh
set -eu

target_dir="${DIFI_CERTIFICATION_DIR:-pcap-tests/DIFI-Certification}"

if [ -d "$target_dir/.git" ]; then
    git -C "$target_dir" fetch --tags --prune
else
    git clone https://github.com/DIFI-Consortium/DIFI-Certification "$target_dir"
fi
