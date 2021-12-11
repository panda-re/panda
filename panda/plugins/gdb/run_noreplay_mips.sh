#/bin/bash
cargo build --no-default-features --features=mips && \
    cp target/debug/libpanda_gdb.so $PANDA_PATH/mips-softmmu/panda/plugins/panda_gdb.so && \
    $PANDA_PATH/mips-softmmu/panda-system-mips -L $PANDA_PATH/pc-bios -os linux-64-debian:3.2.0-4-arm-pae -panda "gdb:on_entry=1" -m 1G ~/.panda/debian_7.3_mips.qcow -nographic -loadvm root -M malta -kernel ~/.panda/vmlinux-3.2.0-4-4kc-malta -append "root=/dev/sda1"
