from pandare import Panda
from sys import argv

arch = argv[1] if len(argv) > 1 else "i386"
panda = Panda(generic=arch)

if arch in ["arm", "mips", "mipsel"]:
    program_name = "wget"
else:
    program_name = "curl"

command_str = f"{program_name} --no-check-certificate  http://www.ll.mit.edu/sites/default/files/styles/ifde_wysiwyg__floated/public/other/image/2018-04/New_Full_Logo-BLACK-2500-lissajou-only-square.png -O o.png"

@panda.queue_async
def driver():
    print(panda.revert_sync("root"))
    print(panda.run_serial_cmd(command_str))
    print(panda.run_serial_cmd("ldd $(which grep)"))
    panda.end_analysis()

@panda.hook_symbol(None, "strlen")
def strlen(env, tb, h):
    print("Strlen hook running")
    h.enabled = False

@panda.hook_symbol("libc", None)
def libc(env, tb, h):
    print("any_libc running")
    h.enabled = False

panda.run()
