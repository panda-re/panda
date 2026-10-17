#!/bin/bash
# One pinned protobuf compiler/C++ library for all PANDA bindings.
# protobuf-c is a separate dependency and remains installed through apt.
set -euo pipefail

protobuf_version=3.21.12
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
curl --fail --location --retry 3 \
    "https://github.com/protocolbuffers/protobuf/releases/download/v21.12/protobuf-cpp-${protobuf_version}.tar.gz" \
    -o "$work_dir/protobuf.tar.gz"
echo "4eab9b524aa5913c6fffb20b2a8abf5ef7f95a80bc0701f3a6dbb4c607f73460  $work_dir/protobuf.tar.gz" | sha256sum --check

tar -xzf "$work_dir/protobuf.tar.gz" -C "$work_dir"
cd "$work_dir/protobuf-$protobuf_version"
# PIC static libraries work inside libpanda/plugins and avoid introducing a
# new shared-library dependency that Ubuntu 22.04 cannot provide to .deb users.
./configure --prefix=/usr/local --disable-shared --with-pic
make -j"$(nproc)"
make install
/usr/local/bin/protoc --version
