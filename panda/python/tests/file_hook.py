#!/usr/bin/env python3
# Test to ensure the file_hook plugin is working

import sys
from pandare import *
from pandare.extras import FileHook

arch = sys.argv[1] if len(sys.argv) > 1 else "i386"
panda = Panda(generic=arch)

# Replace all syscalls that reference /foo with /etc/passwd
hook = FileHook(panda)
hook.rename_file("/foo", "/etc/passwd")

@blocking
def read_it():
    panda.revert_sync('root')
    data = panda.run_serial_cmd("cat /foo")
    assert("root:x:0" in data), f"Failed to read renamed /foo (/etc/passwd): {data}"
    panda.end_analysis()

panda.queue_async(read_it)
panda.run()
print("Successfully hooked /foo to become /etc/passwd")
