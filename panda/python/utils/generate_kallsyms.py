#!/usr/bin/env python3

from pandare import Panda, blocking
from sys import argv
import pickle

# No arguments, i386. Otherwise argument should be guest arch
generic_type = argv[1] if len(argv) > 1 else "i386"
panda = Panda(generic=generic_type)

@blocking
def run_cmd():
    # First revert to root snapshot, then type a command via serial
    panda.revert_sync("root")
    syms = panda.run_serial_cmd("cat /boot/System.map*")

    kallsyms = {}
    for line in syms.split("\n"):
        line = line.strip()
        addr = int(line.split(" ")[0], 16)
        name = line.split(" ")[-1]
        kallsyms[name] = addr

    with open("i386_syms.pickle", "wb") as f:
        pickle.dump(kallsyms, f)
    print("Saved {} symbols".format(len(kallsyms.keys())))

    panda.run_monitor_cmd("quit")

panda.queue_async(run_cmd)

panda.run()
