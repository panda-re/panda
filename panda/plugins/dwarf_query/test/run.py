#!/usr/bin/env python3

from sys import argv
from panda import blocking, Panda

# No arguments, i386. Otherwise argument should be guest arch
generic_type = argv[1] if len(argv) > 1 else "i386"

panda = Panda(
    generic = generic_type,
    extra_args = "-nographic"
)

panda.load_plugin('dwarf_query', args={"json":"./firmadyne_mips_be_2.json"})

@blocking
def run_cmd():
    panda.revert_sync("root")

    # TODO: replace with query API calls
    print(panda.run_serial_cmd("dhclient -v -4"))

panda.queue_async(run_cmd)

panda.run()
