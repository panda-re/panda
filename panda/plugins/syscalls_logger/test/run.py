#!/usr/bin/env python3

from sys import argv
from panda import blocking, Panda

# No arguments, i386. Otherwise argument should be guest arch
generic_type = argv[1] if len(argv) > 1 else "i386"

panda = Panda(
    generic = generic_type,
    extra_args = "-nographic -pandalog test_sys_logger.plog",
    expect_prompt = rb"root@ubuntu:.*",
)

panda.load_plugin('syscalls_logger')

@blocking
def run_cmd():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("dhclient -v -4")) # Networking and write syscalls
    panda.panda_finish()
    panda.end_analysis()

panda.queue_async(run_cmd)

panda.run()