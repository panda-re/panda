from pandare import Panda
from sys import argv

arch = argv[1] if len(argv) > 1 else "i386"
panda = Panda(generic=arch)

if arch in ["arm", "mips", "mipsel"]:
    program_name = "wget"
else:
    program_name = "curl"

command_str = f"{program_name} http://www.ll.mit.edu/sites/default/files/styles/ifde_wysiwyg__floated/public/other/image/2018-04/New_Full_Logo-BLACK-2500-lissajou-only-square.png -O o.png"

@panda.queue_blocking
def driver():
    print(panda.revert_sync("root"))
    print(panda.run_serial_cmd(command_str))
    print(panda.run_serial_cmd("ldd $(which grep)"))
    panda.end_analysis()

malloc_resolved = False
calloc_resolved = False
malloc_ran = False
calloc_ran = False

@panda.hook_symbol_resolution(None, "calloc")
def calloc_resolve(sh, s, m):
    print(f"Calloc resolved to 0x{s.address:x}")
    global calloc_resolved
    calloc_resolved = True
    sh.enabled = False # got result. no reason to continue

@panda.hook_symbol_resolution(None, "malloc")
def malloc_resolve(sh, s, m):
    print(f"Malloc resolved to 0x{s.address:x}")
    global malloc_resolved
    malloc_resolved = True
    sh.enabled = False # got result. no reason to continue

@panda.hook_symbol(None, "calloc")
def calloc(cpu, tb, h):
    print(f"Calloc hook running at 0x{tb.pc:x}")
    global calloc_ran
    calloc_ran = True
    h.enabled = False # got result. no reason to continue

@panda.hook_symbol(None, "malloc")
def malloc(cpu, tb, h):
    print(f"Malloc hook running at 0x{tb.pc:x}")
    global malloc_ran
    malloc_ran = True
    h.enabled = False # got result. no reason to continue

panda.run()

assert(malloc_resolved), "Malloc symbol resolution hook failed to trigger"
assert(calloc_resolved), "Calloc symbol resolution hook failed to trigger"
assert(malloc_ran), "Malloc hook failed to trigger"
assert(calloc_ran), "Calloc hook failed to trigger"
