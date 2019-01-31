# PyPanda

## Installation

Steps to build (very similar to PANDA):

```
git clone https://github.com/lacraig2/panda.git
cd panda
git checkout pypanda
git submodule update --init dtc
mkdir build
cd build
../build.sh
pip3 install colorama cffi
```

## Using PyPanda

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
@pyp.callback("bool(void*)")
def init(handle):
	progress("init in python. handle="+str(handle))
	panda.register_callback(handle, panda.callback.before_block_exec, before_block_execute)
	return True
```

- @pyp.callback("bool(void*)") - Init functions must contain this decorator. This lets cffi know how to use it as a callback. 
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


##### Callback Types

All callbacks are enumerated in the panda.callback structure. To specify a callback use any member below.


- after_block_exec
- after_block_translate
- after_insn_exec
- after_insn_translate
- after_machine_init
- asid_changed
- before_block_exec
- before_block_exec_invalidate_opt
- before_block_translate
- before_replay_loadvm
- cpu_restore_state
- guest_hypercall
- hd_read
- hd_write
- insn_exec
- insn_translate
- monitor
- panda_cb_last
- phys_mem_after_read
- phys_mem_after_write
- phys_mem_before_read
- phys_mem_before_write
- replay_after_dma
- replay_before_dma
- replay_handle_packet
- replay_hd_transfer
- replay_net_transfer
- replay_serial_read
- replay_serial_receive
- replay_serial_send
- replay_serial_write
- top_loop
- virt_mem_after_read
- virt_mem_after_write
- virt_mem_before_read
- virt_mem_before_write


Example:
```
callback = panda.callback.virt_mem_before_write
```


#### Writing Callbacks
```
@pyp.callback("return_type(arg_1_type,arg_2_type,arg_3_type,...)")
def your_callback_name(arg1,arg2,arg3):
    return variable_of_return_type
```

- Your callback must include a decorator. This lets cffi know how to call your callback.
- Your callback must take the number of variables your decorator specifies.
- Your callback must return the same type as your decorator describes


Example:

```
@pyp.callback("int(CPUState*, TranslationBlock*)")
def before_block_execute(cpustate,transblock):
	progress("before block in python")
	pdb.set_trace()
	return 0
```


##### Callback Decorators

This is a comprehensive list of the decorators you must use for each callback type.

| Callback | Decorator 																		|
| --------------------------------- | : --------------------------------------------------: |
| before_block_exec_invalidate_opt | @pyp.callback("bool(CPUState*, TranslationBlock*)") |
| before_block_exec | @pyp.callback("int(CPUState*, TranslationBlock*)") |
| after_block_exec | @pyp.callback("int(CPUState*, TranslationBlock*)") |
| before_block_translate | @pyp.callback("int(CPUState*, target_ulong)") |
| after_block_translate | @pyp.callback("int(CPUState*, TranslationBlock*)") |
| insn_translate | @pyp.callback("bool(CPUState*, target_ulong)") |
| insn_exec | @pyp.callback("int(CPUState*, target_ulong)") |
| after_insn_translate | @pyp.callback("bool(CPUState*, target_ulong)") |
| after_insn_exec | @pyp.callback("int(CPUState*, target_ulong)") |
| guest_hypercall | @pyp.callback("int(CPUState*)") |
| monitor | @pyp.callback("int(Monitor*, char*)") |
| virt_mem_before_read | @pyp.callback("int(CPUState*, target_ulong, target_ulong, target_ulong)") |
| virt_mem_before_write | @pyp.callback("int(CPUState*, target_ulong, target_ulong, target_ulong, void*)") |
| phys_mem_before_read | @pyp.callback("int(CPUState*, target_ulong, target_ulong, target_ulong)") |
| phys_mem_before_write | @pyp.callback("int(CPUState*, target_ulong, target_ulong, target_ulong, void*)") |
| virt_mem_after_read | @pyp.callback("int(CPUState*, target_ulong, target_ulong, target_ulong, void*)") |
| virt_mem_after_write | @pyp.callback("int(CPUState*, target_ulong, target_ulong, target_ulong, void*)") |
| phys_mem_after_read | @pyp.callback("int(CPUState*, target_ulong, target_ulong, target_ulong, void*)") |
| phys_mem_after_write | @pyp.callback("int(CPUState*, target_ulong, target_ulong, target_ulong, void*)") |
| cb_cpu_restore_state | @pyp.callback("int(CPUState*, TranslationBlock*)") |
| before_loadvm | @pyp.callback("int(void)") |
| asid_changed | @pyp.callback("int(CPUState*, target_ulong, target_ulong)") |
| replay_hd_transfer | @pyp.callback("int(CPUState*, uint32_t, uint64_t , uint64_t , uint32_t )") |
| replay_before_dma | @pyp.callback("int(CPUState*, uint32_t, uint8_t* , uint64_t , uint32_t )") |
| replay_after_dma | @pyp.callback("int(CPUState*, uint32_t , uint8_t* , uint64_t , uint32_t )") |
| replay_handle_packet | @pyp.callback("int(CPUState*, uint8_t *, int , uint8_t , uint64_t )") |
| replay_net_transfer | @pyp.callback("int(CPUState*, uint32_t , uint64_t , uint64_t , uint32_t )") |
| replay_serial_receive | @pyp.callback("int(CPUState*, uint64_t ") |
| replay_serial_read | @pyp.callback("int(CPUState*, uint64_t , uint32_t , uint8_t )") |
| replay_serial_send | @pyp.callback("int(CPUState*, uint64_t , uint8_t )") |
| replay_serial_write | @pyp.callback("int(CPUState*, uint64_t ,uint32_t , uint8_t )") |
| after_machine_init | @pyp.callback("void(CPUState*)") |
| top_loop | @pyp.callback("void(CPUState*)") |


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



