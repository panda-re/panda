#/bin/bash
cargo build --no-default-features --features=ppc && \
    cp target/debug/libpanda_gdb.so $PANDA_PATH/ppc-softmmu/panda/plugins/panda_gdb.so && \
    $PANDA_PATH/ppc-softmmu/panda-system-ppc -L $PANDA_PATH/pc-bios -os linux-64-debian:3.2.0-4-ppc-pae -panda "gdb:on_entry=1" -m 1G ~/.panda/debian_7.3_mips.qcow -nographic -loadvm root
