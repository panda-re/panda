#!/usr/bin/env python3

# POC to demonstrate how pypanda has feature parity with Unicorn

import capstone
from sys import argv
from os import path, remove as os_remove

from panda import Panda, ffi
from panda.arm.helper import dump_regs, registers


code = [ # While true, inc R0. With a nop because I'm bad at shellcoding
    b"\x01\x00\x80\xe2", # add r0, #1
    b"\x01\x10\xa0\xe1", # mov r1, r1 (NOP)
    b"\x10\xf0\x4f\xe2", # sub r15, #16
]
ARM_CODE = b"".join(code)


config_path = "/tmp/config_panda.json"
def make_config(addr=0x1000, size=0x1000):
    # TODO: for each user-specified memory mapping, make it

    # Always make a new config file
    if path.isfile(config_path):
        os_remove(config_path)

    with open(config_path, "w") as f:
        f.write("""{{"memory_mapping": [ {{
          "is_special": false, "is_symbolic": false, "forwarded": false,
          "permissions": "rwx", "name": "mem1", "size": 4096,
          "address": {addr}}} ],
      "entry_address": {addr},
      "kernel": "/dev/null"
    }}""".format(addr = addr))

# Setup memory mappings file
ADDRESS = 0x8000000
make_config(ADDRESS)

# Initialize emulator
args = ["-M", "configurable",
        "-kernel", config_path,
        "-nographic"]
panda = Panda(arch="arm", extra_args=args)

# On machine init, setup reg_writes and mem_writes
@panda.cb_after_machine_init
def my_init(env):
    # Map code into memory
    panda.physical_memory_write(ADDRESS, ARM_CODE)

    # Set registers
    env.env_ptr.regs[registers['R0']] = 0
    env.env_ptr.pc = ADDRESS


# VMI: before each block, print disassembly
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
block_count = 0
@panda.cb_before_block_exec
def before_block(env, tb):
    global block_count
    print(f"Block 0x{block_count:x}")

    pc = panda.current_pc(env)
    code_buf = ffi.new("char[]", tb.size)
    code = panda.virtual_memory_read(env, tb.pc, tb.size)

    for i in md.disasm(code, tb.pc):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

    if block_count == 10:
        print("After 10 blocks, R0 = ", hex(env.env_ptr.regs[registers['R0']]))
        panda.end_analysis()
    block_count += 1

panda.run()
print("Finished emulation")
