'''
Capture output of "dhclient" process from the hypervisor, mirror to log files on the host
'''

import sys

from pandare import blocking, Panda
from pandare.extras import ProcWriteCapture

# No arguments, i386. Otherwise argument should be guest arch
generic_type = sys.argv[1] if len(sys.argv) > 1 else "i386"
panda = Panda(generic=generic_type)

@panda.queue_blocking
def run_cmd():
    pwc = ProcWriteCapture(panda, console_capture = True, proc_name = "dhclient", log_dir = "./pwc_log")

    panda.revert_sync("root")
    panda.run_serial_cmd("date")
    panda.run_serial_cmd("dhclient -v -4")

    print("Captured logs:")
    for fw in pwc.get_files_written():
        print(fw)

panda.run()
