'''
hook_symbol.py

This example downloads a file from the internet, hooks the call to fwrite in
libc and grabs the values being written from virtual memory. It then adds the
values to a saved buffer and writes the file to the local file system.

Run with: python3 hook_symbol.py
'''

from pandare import Panda
from sys import argv

arch = argv[1] if len(argv) > 1 else "arm"
panda = Panda(generic=arch)

if arch == "arm" or "mips" in arch:
    program_name = "wget"
    # I tried and couldn't get it to work with https. but it works on 
    # other architectures.
    command_str = "wget --no-check-certificate  http://www.ll.mit.edu/sites/default/files/styles/ifde_wysiwyg__floated/public/other/image/2018-04/New_Full_Logo-BLACK-2500-lissajou-only-square.png -O o.png"
else:
    program_name = "curl"
    command_str = "curl -k https://www.ll.mit.edu/sites/default/files/styles/ifde_wysiwyg__floated/public/other/image/2018-04/New_Full_Logo-BLACK-2500-lissajou-only-square.png --output o.png"

@panda.queue_blocking
def do_stuff():
    panda.revert_sync("root")
    print(panda.run_serial_cmd(command_str,no_timeout=True))
    panda.end_analysis()

stored_buf = b""

@panda.hook_symbol("libc-", "fwrite")
def hook_fwrite(cpu, tb, h):
    if program_name in panda.get_process_name(cpu):
        data_ptr, size_t, count = panda.arch.get_args(cpu, 3)
        buf = panda.virtual_memory_read(cpu, data_ptr, count*size_t)
        global stored_buf
        stored_buf += buf
        print(f"libc:fwrite called")
    else:
        h.enabled = False

panda.run()

print("writing recovered logo to file system")
with open("logo.png","wb") as f:
    f.write(stored_buf)
