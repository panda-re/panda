#!/usr/bin/env python3

from pandare import Panda
panda = Panda(generic='x86_64')

@panda.queue_blocking
def driver():
    '''
    Asynchronous function that drives guest behavior after PANDA starts

    Load a snapshot where we're logged in, then copy the contents
    of ./copy into the guest, ensure ls is executable, then load the trace
    plugin and run ls. When ls completes, end the analysis
    '''
    panda.revert_sync("root") # Revert to snapshot
    panda.copy_to_guest("copy") # Copy directory into guest
    print(panda.run_serial_cmd("chmod +x ./copy/ls")) # Ensure executable
    panda.load_plugin("trace", {'log': f'example_trace.txt', 'target': 'ls'}) # Trace program named ls
    print(panda.run_serial_cmd("./copy/ls")) # Run ls

    panda.end_analysis() # We're finished here

@panda.ppp("proc_start_linux", "on_rec_auxv")
def proc_start(cpu, tb, auxv):
    procname = panda.ffi.string(auxv.argv[0]).decode(errors='ignore') if auxv.argv[0] != panda.ffi.NULL else "(error)"

    if "ls" in procname:
        print(f"{procname} loaded at 0x{auxv.program_header:x}")

print("Starting PANDA execution")
panda.run()
print("PANDA run finished. Log is at example_trace.txt")
