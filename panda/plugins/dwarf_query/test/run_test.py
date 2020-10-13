#!/usr/bin/env python3

from sys import argv
from panda import blocking, Panda

dtb    = "./test_fw/linux-4.4.138/arch/arm/boot/dts/vexpress-v2p-ca9.dtb"
kernel = "./test_fw/linux-4.4.138/arch/arm/boot/zImage"
rootfs = "./test_fw/ubuntu-base-18.04-base-armhf.img"
append = "root=/dev/vda rw earlyprintk=serial,ttyAMA0 console=ttyAMA0"

panda = Panda(arch = "arm", mem = "1G", extra_args=[

    # Kernel
    "-M", "vexpress-a9", "-kernel", kernel, "-dtb", dtb, "-append", append, "-nographic",

    # Network
    "-net", "nic,netdev=net0",
    "-netdev", "user,id=net0,hostfwd=tcp::5443-:443,hostfwd=tcp::5580-:9080,hostfwd=tcp::2222-:22",

    # FS via Virtio
    "-drive", "if=none,file={},id=rootfs,format=raw".format(rootfs),
    "-device", "virtio-blk-device,drive=rootfs",

    ]
)

dwarf_json = "./test_fw/dwarf_info.json"
osi_kernelinfo = "./test_fw/kernel_info.conf"

panda.set_os_name("linux-32-debian.4.4.138")
panda.load_plugin("osi", args={"disable-autoload": True})
panda.load_plugin("osi_linux", args={"kconf_file": osi_kernelinfo, "kconf_group": "debian:4.4.138:32"})
panda.load_plugin('dwarf_query', args={"json": dwarf_json, "verbose": "true"})

panda.run()
