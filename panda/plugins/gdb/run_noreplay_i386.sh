#/bin/bash
cargo build --no-default-features --features=i386 && \
    cp target/debug/libpanda_gdb.so $PANDA_PATH/i386-softmmu/panda/plugins/panda_gdb.so && \
    $PANDA_PATH/i386-softmmu/panda-system-i386 -L $PANDA_PATH/pc-bios -os linux-32-debian:3.2.0-4-686-pae -panda "gdb:on_entry=1" -m 128M ~/.panda/debian_7.3_x86.qcow -nographic -loadvm root -redir tcp:2222::22
