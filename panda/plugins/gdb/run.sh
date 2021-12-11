#/bin/bash
cargo build && \
    cp ../target/debug/libpanda_gdb.so $PANDA_PATH/x86_64-softmmu/panda/plugins/panda_gdb.so && \
    $PANDA_PATH/x86_64-softmmu/panda-system-x86_64 -os "linux-64-ubuntu:4.15.0-72-generic-noaslr-nokaslr" -replay catmaps -panda gdb:on_entry=1 -m 1G
