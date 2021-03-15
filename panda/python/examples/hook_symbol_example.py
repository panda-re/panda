

from pandare import Panda
from rich import print
from sys import argv
arch = argv[1] if len(argv) > 1 else "i386"
panda = Panda(generic=arch)

'''
the arm generic image does not have "curl"
we could install it OR we could show that it doesn't 
matter which program we use
'''
if arch == "arm":
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
    panda.run_serial_cmd(command_str)
    panda.end_analysis()

@panda.hook_symbol("libc-", "fwrite", procname=program_name)
def hook_symbols(env, tb, h):
    print("write called")

panda.run()