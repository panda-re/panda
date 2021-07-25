'''
ioctl_introspection.py

Bash will issue ioctls on /dev/ttys0 when a command is run
This example demonstrates capture and decoding.

Run with: python3 ioctl_introspection.py
'''

import sys

from pandare import Panda
from pandare.extras import IoctlFaker

# No arguments, i386. Otherwise argument should be guest arch
generic_type = sys.argv[1] if len(sys.argv) > 1 else "i386"
panda = Panda(generic=generic_type)

def print_list_elems(l):
    if not l:
        print("None")
    else:
        for e in l:
            print(e)

@panda.queue_blocking
def run_cmd():

    # Setup faker (forces success returns - although only the decode/log functionality is used in this example)
    ioctl_faker = IoctlFaker(panda, use_osi_linux=True)

    print("\nRunning \'ls -l\' to ensure ioctl() capture is working...\n")

    # First revert to root snapshot, then type a command via serial
    panda.revert_sync("root")
    panda.run_serial_cmd("cd / && ls -l")

    # Check ioctl captures
    faked_rets = ioctl_faker.get_forced_returns()
    normal_rets = ioctl_faker.get_unmodified_returns()

    print("{} faked ioctl returns:".format(len(faked_rets)))
    print_list_elems(faked_rets)
    print("\n")

    print("{} normal ioctl returns:".format(len(normal_rets)))
    print_list_elems(normal_rets)
    print("\n")

    panda.end_analysis()

panda.run()
