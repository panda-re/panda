#/bin/bash
cargo build && \
    cp ../target/debug/libpanda_gdb.so $PANDA_PATH/x86_64-softmmu/panda/plugins/panda_gdb.so && \
    $PANDA_PATH/x86_64-softmmu/panda-system-x86_64 -L $PANDA_PATH/pc-bios -os linux-64-ubuntu:4.15.0-72-generic-noaslr-nokaslr -panda "gdb:file=/bin/cat" -m 1024 ~/.panda/bionic-server-cloudimg-amd64-noaslr-nokaslr.qcow2 -nographic -loadvm root -redir tcp:2222::22
