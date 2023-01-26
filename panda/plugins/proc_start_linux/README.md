Plugin: proc_start_linux
===========

Summary
-------

This plugin uses `syscalls2` to provide the auxiliary vector in Linux systems as a PPP callback.

Arguments
---------

Dependencies
------------
syscalls2.
APIs and Callbacks
------------------

We provide the following PPP callback:

```
void (*on_rec_auxv_t)(CPUState *env, TranslationBlock *tb, struct auxv_values);
```

The structure currently provides many elements of the auxiliary vector that you are quite unlikely to need.

There is no guarantee a kernel sets each value every time. The `struct auv_values` is set to 0 before it is filled. A value provided should be suspect if it is a zero.

Python Example
-------

See [proc_start.py](panda/python/examples/proc_start.py) or [proc_start_linux_demo.py](panda/python/examples/proc_start_linux_demo.py) (copied below):
```python
from pandare import Panda
from sys import argv

arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

@panda.queue_blocking
def guest_interaction():
    panda.revert_sync("root")
    for cmd in ["ls -la", "whoami", "time ls -la"]:
        print(f"{cmd} {panda.run_serial_cmd('LD_SHOW_AUXV=1 '+cmd)}")
    panda.end_analysis()

@panda.ppp("proc_start_linux", "on_rec_auxv")
def recv_auxv(cpu, tb, auxv):
    procname = panda.ffi.string(auxv.execfn)
    print(f"started proc {procname} {auxv.phdr:x} {auxv.entry:x}")

panda.run()
```
