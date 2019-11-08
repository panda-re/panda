# PANDA Case Study: Syscall Monitor from Scratch

To make the information in the preceding sections concrete, we will now show how
to implement a low-overhead x86 system call monitor as a PANDA plugin. To do so,
we will use the `PANDA_CB_INSN_TRANSLATE` and `PANDA_CB_INSN_EXEC` callbacks to
create instrumentation that will execute only when the `sysenter` command is
executed on x86.
See the [PANDA manual][panda-manual] for details on the callbacks.

## Implementation

### Makefile
First, we will create a `Makefile` for our plugin, and place it in
`panda/qemu/panda_plugins/syscalls`:

```Makefile
# Don't forget to add your plugin to config.panda!

# Set your plugin name here. It does not have to correspond to the name
# of the directory in which your plugin resides.
PLUGIN_NAME=syscalls

# Include the PANDA Makefile rules
include ../panda.mak

# If you need custom CFLAGS or LIBS, set them up here
# CFLAGS+=
# LIBS+=

# The main rule for your plugin. Please stick with the panda_ naming
# convention.
panda_$(PLUGIN_NAME).so: $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o
    $(call quiet-command,$(CC) $(QEMU_CFLAGS) -shared -o $(SRC_PATH)/$(TARGET_DIR)/$@ $^ $(LIBS),"  PLUGIN  $@")

all: panda_$(PLUGIN_NAME).so
```

### Plugin code
Next, we'll create the main code for the plugin, and put it in
`panda/qemu/panda_plugins/syscalls.c`:

```C
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"

#include "panda_plugin.h"

#include <stdio.h>
#include <stdlib.h>

bool translate_callback(CPUState *env, target_ulong pc);
int exec_callback(CPUState *env, target_ulong pc);

bool init_plugin(void *);
void uninit_plugin(void *);

// This is where we'll write out the syscall data
FILE *plugin_log;

// Check if the instruction is sysenter (0F 34)
bool translate_callback(CPUState *env, target_ulong pc) {
    unsigned char buf[2];
    cpu_memory_rw_debug(env, pc, buf, 2, 0);
    if (buf[0] == 0x0F && buf[1] == 0x34)
        return true;
    else
        return false;
}

// This will only be called for instructions where the
// translate_callback returned true
int exec_callback(CPUState *env, target_ulong pc) {
#ifdef TARGET_I386
    // On Windows and Linux, the system call id is in EAX
    fprintf(plugin_log,
    	"PC=" TARGET_FMT_lx ", SYSCALL=" TARGET_FMT_lx "\n",
    	pc, env->regs[R_EAX]);
#endif
    return 0;
}

bool init_plugin(void *self) {
// Don't bother if we're not on x86
#ifdef TARGET_I386
    panda_cb pcb;

    pcb.insn_translate = translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    pcb.insn_exec = exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
#endif

    plugin_log = fopen("syscalls.txt", "w");
    if(!plugin_log) return false;
    else return true;
}

void uninit_plugin(void *self) {
    fclose(plugin_log);
}
```

The `init_plugin` function registers the callbacks for instruction translation
and execution. Because we are only implementing an x86 callback monitor, we
wrap the callback registration in an `#ifdef TARGET_I386`; this means that on
other architectures the plugin won't do anything (since no callbacks will be
registered). It also opens up a text file that the plugin will use to log the
system calls executed by the guest; if opening the file fails, `init_plugin`
returns false, which will cause PANDA to unload the plugin immediately.

The `translate_callback` function reads the bytes that make up the instruction
that QEMU is about to translate using `cpu_memory_rw_debug`, and and checks
to see whether it is a `sysenter` instruction. If so, then it returns `true`,
which tells PANDA to insert instrumentation that will cause the `exec_callback`
function to be called when the instruction is executed by the guest.

Inside `exec_callback`, we simply log the current program counter (`EIP`) and
the contents of the `EAX` register, which is used on both Windows and Linux to
hold the system call number.

Finally, in `uninit_plugin`, we simply close the plugin log file.

## Building
To build the plugin, we add it to the list of plugins in
`panda/plugins/config.panda`:

```
sample
taintcap
textfinder
textprinter
syscalls
```

Then run `make` from the BUILD directory:

```
brendan@laredo3:~/hg/panda/build$ make
  CC    /home/brendan/hg/panda/build//x86_64-softmmu//panda_plugins/syscalls.o
  PLUGIN  panda_syscalls.so
  CC    /home/brendan/hg/panda/build//i386-linux-user//panda_plugins/syscalls.o
  PLUGIN  panda_syscalls.so
  CC    /home/brendan/hg/panda/build//arm-linux-user//panda_plugins/syscalls.o
  PLUGIN  panda_syscalls.so
  CC    /home/brendan/hg/panda/build//arm-softmmu//panda_plugins/syscalls.o
  PLUGIN  panda_syscalls.so
```

## Running
Finally, you can run PANDA with the plugin enabled:

```
x86_64-softmmu/panda-system-x86_64 -m 1024 -vnc :0 -monitor stdio \
	-hda /scratch/qcows/qcows/win7.1.qcow2 -loadvm booted -k en-us \
	-panda syscalls
```

When run on a Windows 7 VM, this plugin produces output in `syscalls.txt` that looks like:

```
PC=0000000077bd70b2, SYSCALL=0000000000000153
PC=0000000077bd70b2, SYSCALL=0000000000000188
PC=0000000077bd70b2, SYSCALL=00000000000011fa
PC=0000000077bd70b2, SYSCALL=00000000000011c7
PC=0000000077bd70b2, SYSCALL=00000000000011c7
PC=0000000077bd70b2, SYSCALL=0000000000001232
PC=0000000077bd70b2, SYSCALL=0000000000001232
PC=0000000077bd70b2, SYSCALL=000000000000114d
PC=0000000077bd70b2, SYSCALL=0000000000001275
```

The raw system call numbers could also be translated into their
names, e.g. by using [Volatility's list of Windows 7 system calls][volatility-win7].


[panda-manual]: manual.md
[volatility-win7]: https://code.google.com/p/volatility/source/browse/trunk/volatility/plugins/overlays/windows/win7_sp01_x86_syscalls.py
