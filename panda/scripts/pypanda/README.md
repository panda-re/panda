PYPANDA
========
What is PYPANDA
-
PYPANDA is a modification of PANDA that allows for PANDA plugins to be written in Python.

Instillation
-
Below are the directions to install PYPANDA. These are similar to PANDA.
```
git clone https://github.com/lacraig2/panda.git
cd panda
git checkout pypanda
git submodule update --init dtc
mkdir build
cd build
../build.sh
```

Required Libraries
- cffi
- colorama

### Importing pypanda
```
from pypanda import *
``` 
Currently your script should be in the same folder as the pypanda.py file.


### Set up a Panda instance

```
panda = Panda(arch="i386", mem="128M", os_version="debian:3.2.0-4-686-pae", qcow="/file/path/here", extra_args="") 
```
- arch - string for an architecture
- mem - memory for system
- os_version - string to be passed as "-os"
- qcow - path for qcow for system
- extra_args - any arguments you would like to be passed to QEMU


### Writing a Python Plugin

#### Writing an init function
```
@panda.callback.init
def init(handle):
	progress("init in python. handle="+str(handle))
	panda.register_callback(handle, panda.callback.before_block_exec, before_block_execute)
	return True
```
- @panda.callback.init - Init functions must contain this decorator. This lets cffi know how to use it as a callback. 
- handle - This is a unique identifier. Pass it to register_callback and mostly leave it alone.
- panda.register_callback(...) - next section
- This function must return True or False (or you will run into issues)

#### Registering Callbacks
```
panda.register_callback(handle, callback_type, your_callback_method)
```
- handle - This is a unique identifier for your plugin as an integer.
- callback_type - This is the callback you would like to bind to.
- your_callback_method - This is the method you would like called.

Example:
```
panda.register_callback(handle, panda.callback.before_block_exec, before_block_execute)
```
All callbacks are enumerated in the panda.callback structure. To specify a callback use any member shown in the Valid Callback Locations section.
Example:
```
callback = panda.callback.virt_mem_before_write
```
 ### Writing Callbacks
```
@panda.callback.name_of_callback
def your_callback_name(arg1,arg2,arg3):
    return variable_of_return_type
```

- Your callback must include a decorator. This lets cffi know how to call your callback.
- Your callback must take the number of variables your decorator specifies.
- Your callback must return the same type as your decorator describes


Example:

```
@panda.callback.before_block_exec
def before_block_execute(cpustate,transblock):
	progress("before block in python")
	pdb.set_trace()
	return 0
```

#### Running Recordings

```
panda = Panda(...) # as we saw before
panda.replay("/file/path/here")
```

Note: We will update this once we get it to actually work.


#### Starting up PyPanda

```
panda = Panda(...) # as we saw before
panda.run()
```

This starts the system. No arguments.


Functions in PYPANDA
----------------------------

**function:** register_callback
**args:**
$\qquad$handle$\qquad$ unique ID for the plugin
$\qquad$name	$\qquad$ User given name for the callback
$\qquad$number$\qquad$ Not currently in use
$\qquad$function$\qquad$ Python function to be run on call back
**use:**	Tells PANDA to call a function once a callback has been reached

**function:** run
**args:**	None	
**use:** Starts to run PANDA

**function:** begin_replay
Replays are not currently supported in PYPANDA

**function:** load_plugin
**args:**
	name:$\qquad$ Name of the plugin to load
	args: $\qquad$List of optional arguments for the plugin. Default is []
**use:** Loads a plugin written in C

**function:** load_python_plugin
**args:**
	init_function: $\qquad$Function in python to call first.
	Name:$\qquad$ Name of the plugin to load
**use:** Loads a plugin written in Python

**function:** require
**args:**
	plugin:	$\qquad$C plugin to require
**use:** loads a C plugin required by your plug in.

**function:** in_kernel
**args:**
	cpustate:$\qquad$Current CPU state. Returned to the callback by PANDA
**use:** Returns true it the callback is currently in the kernel

**function:** current_sp
**args:**
	cpustate:$\qquad$Current CPU state. Returned to the callback by PANDA
**use:** Returns the current stack pointer

**function:** get_guest_instr_count 
**args:**	None
**use:**	Returns the current instruction pointer.


Valid Callback Locations
------------------------
**Block changes**

Name|Description
---|---
before_block_translate | Before translating each basic block
after_block_translate | After translating each basic block
before_block_exec_invalidate_opt | Before executing each basic block (with option to invalidate, may trigger retranslation)
before_block_execBefore | Executing each basic block
after_block_exec | After executing each basic block
insn_translate | Before an insn is translated
insn_exec | Before an insn is executed
after_insn_translate | After an insn is translated
after_insn_exec | After an insn is executed

**Before memory changes**
Name|Description
---|---
virt_mem_before_read | Before virtual memory read
virt_mem_before_write |Before virtual memory write
phys_mem_before_read | Before physical memory read
phys_mem_before_write | Before physical memory write

**After Memory changes**
Name|Description
---|---
virt_mem_after_read | After virtual memory read
virt_mem_after_write | After virtual memory write
phys_mem_after_read | After physical memory read
phys_mem_after_write | After physical memory write

**Other**
Name|Description
---|---
hd_read | Each HDD read
hd_write | Ech HDD write
guest_hypercall | Hypercall from the guest (e.g. CPUID)
monitor | Void callback
cpu_restore_state | In cpu_restore_state() (fault/exception)
before_replay_loadvm | At start of replay, before loadvm
asid_changed | When CPU asid (address space identifier) changes
replay_hd_transfer | In replay, hd transfer
replay_net_transfer | In replay, transfers within network card (currently only E1000)
replay_serial_receive | In replay, right after data is pushed into the serial RX FIFO
replay_serial_read | In replay, right after a value is read from the serial RX FIFO.
replay_serial_send | In replay, right after data is popped from the serial TX FIFO
replay_serial_write | In replay, right after data is pushed into the serial TX FIFO.
replay_before_dma | In replay, just before RAM case of cpu_physical_mem_rw
replay_after_dma | In replay, just after RAM case of cpu_physical_mem_rw
replay_handle_packet | In replay, packet in / out
after_machine_init | Right after the machine is initialized, before any code runs

**Top of the loop**
Name|Description
---|---
top_loop | At top of loop that manages emulation.  good place to take a snapshot