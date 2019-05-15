pypanda
========
What is pypanda
-
PYPANDA is an extension of PANDA that allows for PANDA plugins to be written 
in Python.

### Installation
See installation instructions in [here](./docs/installation.md).

### Importing pypanda
```
from pypanda import *
``` 
Currently your script should be in the same folder as the pypanda.py file.


### Set up a Panda instance

```
panda = Panda(arch="i386", mem="128M", os_version="debian:3.2.0-4-686-pae", 
				qcow="/file/path/here", extra_args="") 
```
- arch - string for an architecture
- mem - memory for system
- os_version - string to be passed as "-os"
- qcow - path for qcow for system
- extra_args - any arguments you would like to be passed to QEMU

### Playing with existing plugins


#### [example_after_init.py](example_after_init.py)

This sets up the callback for `after_machine_init`, hits it, and gives the user
a pdb trace.

Run this with `python3 example_after_init.py`

#### [example_coverage.py](example_coverage.py)

This example demonstrates dynamic loading and unloading of the coverage plugin.
It does so by registering the `before_block_execute` callback.

#### [example_disable_callbacks.py](example_disable_callbacks.py)

This example shows registering, enabling, and disabling of callbacks during 
runtime of a program. In particular, it enables `before_block_execute` and
`after_block_execute`. After 2 blocks hit it disables `after_block_execute`. 
After 2 additional blocks hit it enables `after_block_execute` again.
 
Run with: `python3 example_disable_callbacks.py`

#### [example_multiple_callbacks.py](example_multiple_callbacks.py)

This example shows the ability to set up multiple callbacks. The example sets up
`before_block_exec` as well as `after_block_exec`. There is a delay of 1 second 
every time each callback is called. 

Run this with `python3 example_multiple_callbacks.py`

#### [example_network.py](example_network.py)

This example implements the networks same functionality as the network plugin in
panda. It registers `replay_handle_packet` callback, converts the buffer, and
writes the buffer out to a pcap.

Run with: `python3 example_network.py i386 out.pcap /path/to/recording`

#### [example_osi_linux_test.py](example_osi_linux_test.py)

This exampls shows off the functionality of `osi_linux` in pypanda. Modeled
after the original `osi_linux` panda plugin.

Runs with `python3 example_osi_linux_test.py i386 /path/to/recording`

#### [example_plugin.py](example_plugin.py)

This is the simplest of plugins. It registers a callback for `before_block_exec`
and gives the user a pdb trace each time it is hit.

Run this with `python3 example_plugin.py`

#### [example_print_regs.py](example_print_regs.py)

This example displays the register state of the cpu in x86 at each 
`before_block_exec`.

Run this with `python3 example_print_regs.py`

#### [example_record_replay.py](example_record_replay.py)

This example registers asid_changed and runs a replay from a file specified.

Run with: `python3 example_record_replay.py i386 /path/to/recording`

#### [example_virt_mem_read_callback.py](example_virt_mem_read_callback.py)

This plugin registers the `virt_mem_after_write` callback and attempts to find
strings in the buffers.

Run with: `python3 example_virt_mem_read_callback.py`

#### [example_watch_program.py](example_watch_program.py)

This example allows us to debug a specific program by name. It registers 
`asid_changed` and waits for the osi process name to match the name of the
program set by the user.

Run with: `python3 example_watch_program.py`

### Writing a Python Plugin

#### Writing an `init` function
```
@panda.callback.init
def init(handle):
	progress("init in python. handle="+str(handle))
	panda.register_callback(handle, panda.callback.before_block_exec, 
							before_block_execute)
	return True
```
- @panda.callback.init - Init functions must contain this decorator. This lets 
cffi know how to use it as a callback. 
- handle - This is a unique identifier. Pass it to register_callback and mostly
leave it alone.
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
panda.register_callback(handle, panda.callback.before_block_exec, 
						before_block_execute)
```
All callbacks are enumerated in the panda.callback structure. To specify a 
callback use any member shown in the Valid Callback Locations section.
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

- Your callback must include a decorator. This lets cffi know how to call your 
callback.
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
panda.begin_replay("/file/path/here")
```

Note: We will update this once we get it to actually work.


#### Starting up PyPanda

```
panda = Panda(...) # as we saw before
panda.run()
```

This starts the system. No arguments.

#### Functions in pypanda
----------------------------

**function:** register_callback
**args:**
- handle - unique ID for the plugin
- name - User given name for the callback
- number - Not currently in use
- function - Python function to be run on call back
**use:**	Tells PANDA to call a function once a callback has been reached

**function:** run
**args:**	None	
**use:** Starts to run PANDA

**function:** begin_replay
Replays are not currently supported in PYPANDA

**function:** load_plugin
**args:**
- name - Name of the plugin to load
- args - List of optional arguments for the plugin. Default is []
**use:** Loads a plugin written in C

**function:** load_python_plugin
**args:**
- init_function - Function in python to call first.
- Name - Name of the plugin to load
**use:** Loads a plugin written in Python

**function:** require
**args:**
- plugin - C plugin to require
**use:** loads a C plugin required by your plug in.

**function:** in_kernel
**args:**
- cpustate - Current CPU state. Returned to the callback by PANDA
**use:** Returns true it the callback is currently in the kernel

**function:** current_sp
**args:**
- cpustate - Current CPU state. Returned to the callback by PANDA
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
