#!/usr/bin/env python3

# Run the date command in the guest, identify all strings compared to 'America',
# since that's the start of the timezone we set. We should see relevant strings
# like EDT or EST in a comparison at some point.

from sys import argv
from os import path
from pandare import Panda

LOG_ALL = False
LOG_UNIQUE = True

arch = "x86_64" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

panda.load_plugin("callstack_instr")
panda.load_plugin("callwitharg", {"targets": "America", "verbose": False})
interesting_args = set()

@panda.ppp("callwitharg", "on_call_match_str")
def on_match(cpu, func_addr, args, str_match, match_idx, n_args_read):
    # Report on every match

    if LOG_ALL:
        print(f"String match at {func_addr:x} for {panda.ffi.string(str_match)} in arg {match_idx}")
        for i in range(n_args_read):
            try:
                str_arg = panda.read_str(cpu, args[i])
            except ValueError:
                str_arg = f"(error reading {args[i]:#x})"

            print("\t", repr(str_arg))

    if LOG_UNIQUE:
        for i in range(n_args_read):
            if i == match_idx:
                continue
            try:
                str_arg = panda.read_str(cpu, args[i])
            except ValueError:
                continue
            if len(str_arg):
                interesting_args.add(str_arg)

@panda.queue_blocking
def driver():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("TZ=America/New_York date"))
    panda.end_analysis()

panda.run()

if LOG_UNIQUE:
    for arg in interesting_args:
        print(repr(arg))
