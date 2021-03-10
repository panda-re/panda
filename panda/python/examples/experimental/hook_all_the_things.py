

from pandare import Panda
from rich import print, inspect
from sys import argv
arch = argv[1]
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


from os.path import exists

recording_name = "curlfile"+arch

if not exists(f"{recording_name}-rr-snp"):
    print("recordig did not exist")
    @panda.queue_blocking
    def do_stuff():
        panda.revert_sync("root")
        panda.run_monitor_cmd(f"begin_record {recording_name}")
        print(panda.run_serial_cmd(command_str))
        print(panda.run_serial_cmd("ls -la"))
        panda.run_monitor_cmd("end_record")
        panda.stop_run()
    panda.run()
else:
    print("recording exists. not remaking recording")

from functools import lru_cache

@lru_cache
def lookup_name(asid,env):
    return panda.get_process_name(env)
output = ""

@panda.hook_symbol(None, None, procname="curl")
def hook_symbols(env, tb, h):
    procname = lookup_name(panda.current_asid(env), env)
    spacer1 = (50 - len(procname))* ' '
    libname = panda.ffi.string(h.sym.section)
    spacer2 = (50 - len(libname))* ' '
    symname = panda.ffi.string(h.sym.name)
    print(f"[bold magenta]{procname}[/bold magenta]{spacer1}[bold yellow]{libname}[/bold yellow]{spacer2}[bold red]{symname}[/bold red]")

panda.run_replay(recording_name)