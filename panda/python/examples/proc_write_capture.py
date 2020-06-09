'''
Capture stdout of "whoami" from the hypervisor, write to a log file on the host
Also works for stderr and any file written by the target process
'''

import sys

from panda import blocking, Panda
from panda.extras.proc_write_capture import ProcWriteCapture

# No arguments, i386. Otherwise argument should be guest arch
generic_type = sys.argv[1] if len(sys.argv) > 1 else "i386"
panda = Panda(generic=generic_type)

@blocking
def run_cmd():

    pwc = ProcWriteCapture(panda, "dhclient", log_dir = "./poc_log")

    panda.revert_sync("root")
    panda.run_serial_cmd("dhclient -v -4")

    print("Captured logs:")
    for fw in pwc.get_files_written():
        print(fw)

panda.queue_async(run_cmd)
panda.run()
