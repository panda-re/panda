# PANDA Plugins

This document describes the plugin architecture for PANDA, the Platform
for Architecture-Neutral Dynamic Analysis. Plugins are an easy way to extend the features of PANDA, and allow a wide range of dynamic analyses to be implemented without modifying QEMU.

## Using Plugins

If all you want to do is use plugins others have written, you can read this section and skip the rest.

There are two ways to load a PANDA plugin: by specifying it via `-panda` or `-panda-plugin` on the QEMU command line, or by using the `load_plugin` command from the monitor. If using `-panda-plugin` or `load_plugin`, the plugin should be specified by giving the path to the plugin (which will usually be named `panda_{something}.so`).

If using `-panda`, specify just the plugin's name. PANDA will search for the plugin in either the QEMU directory or in PANDA_PLUGIN_DIR. You can specify multiple plugins as a semicolon-separated list, and you can give the plugins arguments as a comma-separated list after the plugin's name and a colon. For example:

	-panda 'stringsearch;callstack_instr;llvm_trace:base=dir,foo=bar'

This loads the `stringsearch`, `callstack_instr`, and `llvm_trace` plugins and passes `llvm_trace` the arguments `base=dir` and `foo=bar`. Note that the `;` character must be escaped in most shells; you can either surround the arguments with quotes (as in this example) or just escape the semicolon itself, e.g. `base=dir\;foo=bar`.

Once a plugin is loaded, it will appear when using the `list_plugins` monitor command:

	(qemu) list_plugins 
	idx     name                    addr
	0       panda_syscalls.so       0x1ee46b0

While the plugin is running, you can also use `plugin_cmd "cmd"` to send commands to the plugin using the monitor. In general, plugins should implement the `help` command if they support any monitor commands, so running `plugin_cmd help` should show usage information for all loaded plugins. The command is sent to the plugin as a single string, so make sure to quote the command properly.

To unload a plugin, either quit QEMU (which automatically unloads all plugins), or use the monitor command `unload_plugin <idx>`, where `idx` is the index shown in `list_plugins`.


## Plugin Setup

To create a new PANDA plugin, create a new directory inside `qemu/panda_plugins`, and copy `Makefile.example` into `qemu/panda_plugins/${YOUR_PLUGIN}/Makefile`. Then edit the Makefile to suit the needs of your plugin (at minimum, you should change the plugin name). By default, the source file for your plugin must be named `${YOUR_PLUGIN}.(c|cpp)`, but this can be changed by editing the Makefile.

To actually have your plugin compiled as part of the main QEMU build process, you should add it to `qemu/panda_plugins/config.panda`, which looks like:

	PANDA_PLUGINS = sample taintcap textfinder textprinter syscalls

Plugins can currently be written in either C or C++.

When you run `make`, the QEMU build system will build your plugin for each target architecture that was specified in `./configure --target-list=`. This means that architecture-specific parts of your plugin should be guarded using code like:

    #if defined(TARGET_I386)
    // Do x86-specific stuff
    #elif defined(TARGET_ARM)
    // Do ARM-specific stuff
    #endif
    
It also means that your code can use the various target-specific macros, such as `target_ulong`, in order to get code that works with all of QEMU's architectures.


## Personal Plugins 

You can also pull plugin code from some other directory, i.e., not from `panda/qemu/panda_plugins`.  This allows you to maintain a separate repository of your personal plugins.  

1. Create a directory in which you will create personal plugins.  `/home/you/personal_plugins`
2. Create a subdirectory `personal_plugins/panda_plugins` there as well.
3. Copy `panda/qemu/extra_plugins_panda.mak` into that `panda_plugins` subdir.  Fix `SRC_PATH` variable in that file.
4. Say you have written a plugin you want to call `new_cool`.  Create a subdirectory `panda_plugins/new_cool` and put the code for the new plugin there.
5. Create a file `panda_plugins/config.panda` with names of enabled plugins as you would normally.
6. You can use the the same makefile set-up as with regular plugins.  However, you'll have to `include ../extra-plugins-panda.mak` and not `panda.mak`
7. configure with `--extra-plugins-path=/home/you/personal_plugins`
8. Build as usual and you should compile `new_cool` plugin and its code will be deposited in, e.g., `i386-softmmu/panda_plugins`

        
    
## Plugin Initialization and Shutdown

All plugins are required to contain, at minimum, two functions with the
following signatures:

	bool init_plugin(void *self);
  	void uninit_plugin(void *self);

The single void * parameter is a handle to the plugin; because this comes from `dlopen`, it can be safely used with `dlsym` and friends. This handle is also what should be passed to `panda_register_callback` in order to register a plugin function as a callback.

In general, `init_plugin` will perform any setup the plugin needs, and call `panda_register_callback` to tell PANDA what plugin functions to call for various events. For example, to register a callback that will be executed after the execution of each basic block, you would use the following code:

    pcb.after_block_exec = after_block_callback;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);

The `uninit_plugin` function will be called when the plugin is unloaded. You should free any resources used by the plugin here, as plugins can be unloaded from the monitor – so you can't rely on QEMU doing all your cleanup for you.

## Plugin API

### Callback and Plugin Management

	void panda_register_callback(void *plugin, panda_cb_type type, panda_cb cb);

Registers a callback with PANDA. The `type` parameter specifies what type of
callback, and `cb` is used for the callback itself (`panda_cb` is a union of all
possible callback signatures). Callbacks prefixed with PANDA_CB_USER are for
QEMU user-mode only. The callback types currently defined are:

    PANDA_CB_BEFORE_BLOCK_TRANSLATE,    // Before translating each basic block
    PANDA_CB_AFTER_BLOCK_TRANSLATE,     // After translating each basic block
    PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT,    // Before executing each basic block (with option to invalidate, may trigger retranslation)
    PANDA_CB_BEFORE_BLOCK_EXEC,         // Before executing each basic block
    PANDA_CB_AFTER_BLOCK_EXEC,          // After executing each basic block
    PANDA_CB_INSN_TRANSLATE,    // Before an instruction is translated
    PANDA_CB_INSN_EXEC,         // Before an instruction is executed
    PANDA_CB_VIRT_MEM_READ,     // After each memory read (virtual addr.)
    PANDA_CB_VIRT_MEM_WRITE,    // Before each memory write (virtual addr.)
    PANDA_CB_PHYS_MEM_READ,     // After each memory read (physical addr.)
    PANDA_CB_PHYS_MEM_WRITE,    // Before each memory write (physical addr.)
    PANDA_CB_GUEST_HYPERCALL,   // Hypercall from the guest (e.g. CPUID)
    PANDA_CB_MONITOR,           // Monitor callback
    PANDA_CB_LLVM_INIT,         // On LLVM JIT initialization
    PANDA_CB_CPU_RESTORE_STATE,  // In cpu_restore_state() (fault/exception)
    PANDA_CB_USER_BEFORE_SYSCALL, // before system call
    PANDA_CB_USER_AFTER_SYSCALL,  // after system call (with return value)

For more information on each callback, see the "Callbacks" section.
	
	void * panda_get_plugin_by_name(const char *name);
	
Retrieves a handle to a plugin, given its name (the name is just the base name of the plugin's filename; that is, if the path to the plugin is `qemu/panda/panda_test.so`, the plugin name will be `panda_test.so`).

This can be used to allow one plugin to call functions another, since the handle returned is usable with `dlsym`.

	bool   panda_load_plugin(const char *filename);

Load a PANDA plugin. The `filename` parameter is currently interpreted as a simple filename; no searching is done (this may change in the future). This can be used to allow one plugin to load another.

	void   panda_unload_plugin(void *plugin);

Unload a PANDA plugin. This can be used to allow one plugin to unload another one.

	void   panda_disable_plugin(void *plugin);

Disables callbacks registered by a PANDA plugin. This can be used to allow one plugin to temporarily disable another one.

	void   panda_enable_plugin(void *plugin);

Enables callbacks registered by a PANDA plugin. This can be used to re-enable callbacks of a plugin that was disabled.


### Argument handling

PANDA allows plugins to receive options on the command line. Each option should look like `-panda-arg <plugin_name>:<key>=<value>`.

    typedef struct panda_arg {
        char *argptr;   // For internal use only
        char *key;      // Pointer to the key string
        char *value;    // Pointer to the value string
    } panda_arg;

    typedef struct panda_arg_list {
        int nargs;
        panda_arg *list;
    } panda_arg_list;

    panda_arg_list *panda_get_args(const char *plugin_name);

Retrieves a list of just the PANDA arguments that match `plugin_name`. The arguments are returned in a `panda_arg_list` structure, where the `nargs` member gives the length of the `list` of individual `panda_arg` structures. Each `panda_arg` has a `key`/`value` pair. Note that calling `panda_get_args` allocates memory to store the list, which should be freed after use with `panda_free_args`.

    void panda_free_args(panda_arg_list *args);

Frees an argument list created with `panda_get_args`.

### Runtime QEMU Control

	void panda_do_flush_tb(void);
	
Requests that the translation block cache be flushed as soon as possible. If running with translation block chaining turned off (e.g. when in LLVM mode or replay mode), this will happen when the current translation block is done executing.

Flushing the translation block cache is necessary if the plugin makes changes to the way code is translated (for example, by using `panda_enable_precise_pc`). **WARNING**: failing to flush the TB before turning on something that alters code translation may cause QEMU to crash! This is because QEMU's interrupt handling mechanism relies on translation being deterministic (see the `search_pc` stuff in translate-all.c for details).
	
	void panda_enable_memcb(void);
	void panda_disable_memcb(void);

These functions enable and disable the memory callbacks (PANDA_CB_MEM_READ and PANDA_CB_MEM_WRITE). Because of the overhead of implementing memory callbacks, these are not on by default. They are implemented by setting a flag that both LLVM and TCG check that will cause them to use the instrumented versions _mmu functions, enabling the memory callbacks.

	void panda_disable_tb_chaining(void);
	void panda_enable_tb_chaining(void);

These functions allow plugins to selectively turn translation block chaining on
and off, regardless of whether the backend is TCG or LLVM, and independent of
record and replay.

	void panda_enable_precise_pc(void);
	void panda_disable_precise_pc(void);

Enables or disables precise tracking of the program counter. By default, QEMU does not update the program counter after every instruction, so code that relies on knowing the exact value of the PC should use these functions to change that. After enabling precise PC tracking, the program counter will be available in `env->panda_guest_pc` and can be assumed to accurately reflect the guest state.

    int panda_physical_memory_rw(target_phys_addr_t addr, uint8_t *buf, int len, int is_write);

Read or write `len` bytes of guest physical memory at `addr` into or from the supplied buffer `buf`. This function differs from QEMU's `cpu_physical_memory_rw` in that it will never access I/O, only RAM. This function returns zero on success, and negative values on failure.

    int panda_virtual_memory_rw(CPUState *env, target_ulong addr, uint8_t *buf, int len, int is_write);

Read or write `len` bytes of guest virtual memory at `addr` into or from the supplied buffer `buf`. This function differs from QEMU's `cpu_memory_rw_debug` in that it will never access I/O, only RAM. This function returns zero on success, and negative values on failure.

    void panda_enable_llvm(void);
    void panda_disable_llvm(void);

These functions enable and disable the use of the LLVM JIT in replacement of the
TCG backend.  Here, an additional translation step is added from the TCG IR to
the LLVM IR, and that is executed on the LLVM JIT.  Currently, this only works
when QEMU is starting up, but we are hoping to support dynamic configuration of
code generation soon.

    void panda_enable_llvm_helpers(void);
    void panda_disable_llvm_helpers(void);

These functions enable and disable the execution of QEMU helper functions in the
LLVM JIT.  Call the enable function after calling panda_enable_llvm(), and call
the disable function before calling panda_disable_llvm().

    void panda_memsavep(FILE *out);

Saves a physical memory snapshot into the open file pointer `out`. This function
is guaranteed not to perturb guest state.

## Callbacks

---

**before_block_exec_invalidate_opt**: called before execution of every basic
block, with the option to invalidate the TB

**Callback ID**: PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT

**Arguments**:

* `CPUState *env`: the current CPU state
* `TranslationBlock *tb`: the TB we are about to execute

**Return value**:

`true` if we should invalidate the current translation block and retranslate, `false` otherwise

**Signature**:

    bool (*before_block_exec_invalidate_opt)(CPUState *env, TranslationBlock *tb);

---

**before_block_exec**: called before execution of every basic block

**Callback ID**: PANDA_CB_BEFORE_BLOCK_EXEC

**Arguments**:

* `CPUState *env`: the current CPU state
* `TranslationBlock *tb`: the TB we are about to execute

**Return value**:

unused

**Signature**:

    int (*before_block_exec)(CPUState *env, TranslationBlock *tb);

---

**after_block_exec**: called after execution of every basic block

**Callback ID**: PANDA_CB_AFTER_BLOCK_EXEC

**Arguments**:

* `CPUState *env`: the current CPU state
* `TranslationBlock *tb`: the TB we just executed
* `TranslationBlock *next_tb`: the TB we will execute next (may be `NULL`)

**Return value**:

unused

**Signature:**:
 
    int (*after_block_exec)(CPUState *env, TranslationBlock *tb, TranslationBlock *next_tb);

---

**before_block_translate**: called before translation of each basic block

**Callback ID**: PANDA_CB_BEFORE_BLOCK_TRANSLATE

**Arguments**:

* `CPUState *env`: the current CPU state
* `target_ulong pc`: the guest PC we are about to translate

**Return value**:

unused

**Signature**:

	int (*before_block_translate)(CPUState *env, target_ulong pc);

---

**after_block_translate**: called after the translation of each basic block

**Callback ID**: PANDA_CB_AFTER_BLOCK_TRANSLATE

**Arguments**:

* `CPUState *env`: the current CPU state
* `TranslationBlock *tb`: the TB we just translated

**Return value**:

unused

**Notes**:

This is a good place to perform extra passes over the generated
code (particularly by manipulating the LLVM code)
**FIXME**: How would this actually work? By this point the out ASM
has already been generated. Modify the IR and then regenerate?

**Signature**:

	int (*after_block_translate)(CPUState *env, TranslationBlock *tb);

---

**insn_translate**: called before the translation of each instruction

**Callback ID**: PANDA_CB_INSN_TRANSLATE

**Arguments**:

* `CPUState *env`: the current CPU state
* `target_ulong pc`: the guest PC we are about to translate

**Return value**:

`true` if PANDA should insert instrumentation into the generated code,
`false` otherwise

**Notes**:

This allows a plugin writer to instrument only a small number of
instructions, avoiding the performance hit of instrumenting everything.
If you do want to instrument every single instruction, just return
true. See the documentation for `PANDA_CB_INSN_EXEC` for more detail.

**Signature**:

	bool (*insn_translate)(CPUState *env, target_ulong pc);

---

**insn_exec**: called before execution of any instruction identified
by the `PANDA_CB_INSN_TRANSLATE` callback

**Callback ID**: PANDA_CB_INSN_EXEC

**Arguments**:

* `CPUState *env`: the current CPU state
* `target_ulong pc`: the guest PC we are about to execute

**Return value**:

unused

**Notes**:

This instrumentation is implemented by generating a call to a
helper function just before the instruction itself is generated.
This is fairly expensive, which is why it's only enabled via
the `PANDA_CB_INSN_TRANSLATE` callback.

**Signature**:

	int (*insn_exec)(CPUState *env, target_ulong pc);

---

**guest_hypercall**: called when a program inside the guest makes a
hypercall to pass information from inside the guest to a plugin

**Callback ID**: PANDA_CB_GUEST_HYPERCALL

**Arguments**:

* `CPUState *env`: the current CPU state

**Return value**:

unused

**Notes**:

On x86, this is called whenever CPUID is executed. Plugins then check for magic
values in the registers to determine if it really is a guest hypercall.
Parameters can be passed in other registers.  We have modified translate.c to
make CPUID instructions end translation blocks.  This is useful, if, for
example, you want to have a hypercall that turns on LLVM and enables heavyweight
instrumentation at a specific point in execution.

S2E accomplishes this by using a (currently) undefined opcode. We
have instead opted to use an existing instruction to make development
easier (we can use inline asm rather than defining the raw bytes).

AMD's SVM and Intel's VT define hypercalls, but they are privileged
instructions, meaning the guest must be in ring 0 to execute them.

For hypercalls in ARM, we use the MCR instruction (move to coprocessor from ARM
register), moving to coprocessor 7.  CP 7 is reserved by ARM, and isn't
implemented in QEMU.  The MCR instruction is present in all versions of ARM, and
it is an unprivileged instruction in this scenario.  Plugins can also check for
magic values in registers on ARM.

**Signature**:

	int (*guest_hypercall)(CPUState *env);

---

**monitor**: called when someone uses the `plugin_cmd` monitor command

**Callback ID**: PANDA_CB_MONITOR

**Arguments**:

* `Monitor *mon`: a pointer to the Monitor
* `const char *cmd`: the command string passed to plugin_cmd

**Return value**:

unused

**Notes**:

The command is passed as a single string. No parsing is performed
on the string before it is passed to the plugin, so each plugin
must parse the string as it deems appropriate (e.g. by using `strtok`
and `getopt`) to do more complex option processing.

It is recommended that each plugin implementing this callback respond
to the "help" message by listing the commands supported by the plugin.

Note that every loaded plugin will have the opportunity to respond to
each `plugin_cmd`; thus it is a good idea to ensure that your plugin's
monitor commands are uniquely named, e.g. by using the plugin name
as a prefix (`sample_do_foo` rather than `do_foo`).

**Signature**:

	int (*monitor)(Monitor *mon, const char *cmd);

---

**virt_mem_read**: called after memory is read

**Callback ID**: PANDA_CB_VIRT_MEM_READ

**Arguments**:

* `CPUState *env`: the current CPU state
* `target_ulong pc`: the guest PC doing the read
* `target_ulong addr`: the (virtual) address being read
* `target_ulong size`: the size of the read
* `void *buf`: pointer to the data that was read

**Return value**:

unused

**Notes**:

You must call `panda_enable_memcb()` to turn on memory callbacks
before this callback will take effect.

**Signature**:

	int (*virt_mem_read)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

---

**virt_mem_write**: called before memory is written

**Callback ID**: PANDA_CB_VIRT_MEM_WRITE

**Arguments**:

* `CPUState *env`: the current CPU state
* `target_ulong pc`: the guest PC doing the write
* `target_ulong addr`: the (virtual) address being written
* `target_ulong size`: the size of the write
* `void *buf`: pointer to the data that is to be written 

Return value:

unused

**Notes**:

You must call `panda_enable_memcb()` to turn on memory callbacks
before this callback will take effect.

**Signature**:

	int (*virt_mem_write)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

---

**phys_mem_read**: called after memory is read

**Callback ID**: PANDA_CB_PHYS_MEM_READ

**Arguments**:

* `CPUState *env`: the current CPU state
* `target_ulong pc`: the guest PC doing the read
* `target_ulong addr`: the (physical) address being read
* `target_ulong size`: the size of the read
* `void *buf`: pointer to the data that was read

**Return value**:

unused

**Notes**:

You must call `panda_enable_memcb()` to turn on memory callbacks
before this callback will take effect.

**Signature**:

	int (*phys_mem_read)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

---

**phys_mem_write**: called before memory is written

**Callback ID**: PANDA_CB_PHYS_MEM_WRITE

**Arguments**:

* `CPUState *env`: the current CPU state
* `target_ulong pc`: the guest PC doing the write
* `target_ulong addr`: the (physical) address being written
* `target_ulong size`: the size of the write
* `void *buf`: pointer to the data that is to be written 

Return value:

unused

**Notes**:

You must call `panda_enable_memcb()` to turn on memory callbacks
before this callback will take effect.


**Signature**:

	int (*phys_mem_write)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

---

**cb_cpu_restore_state**: Called inside of cpu_restore_state(), when there is a
CPU fault/exception

**Callback ID**: PANDA_CB_CPU_RESTORE_STATE

**Arguments**:

* `CPUState *env`: the current CPU state
* `TranslationBlock *tb`: the current translation block
       
**Return value**: unused

**Signature**:

    int (*cb_cpu_restore_state)(CPUState *env, TranslationBlock *tb);

---

**user_before_syscall**: Called before a syscall for QEMU user mode.

**Callback ID**: PANDA_CB_USER_BEFORE_SYSCALL
       
**Arguments**:

* `void *cpu_env`: pointer to CPUState
* `bitmask_transtbl *fcntl_flags_tbl`: syscall flags table from syscall.c
* `int num`: syscall number
* `abi_long arg1..arg8`: syscall arguments

**Return value**: unused

**Notes**:
Some system call arguments need some additional processing, as evident in
linux-user/syscall.c.  If your plugin is particularly interested in system call
arguments, be sure to process them in similar ways.

Additionally, this callback is dependent on running qemu in linux-user mode,
a mode for which PANDA support is being phased out. To use this callback you
will need to wrap the code in #ifdefs. See the 'taint' or 'llvm_trace' PANDA 
plugins for examples of legacy usage. This callback will likely be removed in 
future versions of PANDA.

**Signature**:

    int (*user_before_syscall)(void *cpu_env, bitmask_transtbl *fcntl_flags_tbl,
                               int num, abi_long arg1, abi_long arg2, abi_long
                               arg3, abi_long arg4, abi_long arg5,
                               abi_long arg6, abi_long arg7, abi_long arg8);
---

**user_after_syscall**: Called after a syscall for QEMU user mode

**Callback ID**: PANDA_CB_USER_AFTER_SYSCALL

**Arguments**:

* `void *cpu_env`: pointer to CPUState
* `bitmask_transtbl *fcntl_flags_tbl`: syscall flags table from syscall.c
* `int num`: syscall number
* `abi_long arg1..arg8`: syscall arguments
* `void *p`: void pointer used for processing of some arguments
* `abi_long ret`: return value of syscall
       
**Return value**: unused

**Notes**:
Some system call arguments need some additional processing, as evident in
linux-user/syscall.c.  If your plugin is particularly interested in system call
arguments, be sure to process them in similar ways.

Additionally, this callback is dependent on running qemu in linux-user mode,
a mode for which PANDA support is being phased out. To use this callback you
will need to wrap the code in #ifdefs. See the 'taint' or 'llvm_trace' PANDA 
plugins for examples of legacy usage. This callback will likely be removed in 
future versions of PANDA.

**Signature**:

    int (*user_after_syscall)(void *cpu_env, bitmask_transtbl *fcntl_flags_tbl,
                              int num, abi_long arg1, abi_long arg2, abi_long
                              arg3, abi_long arg4, abi_long arg5, abi_long arg6,
                              abi_long arg7, abi_long arg8, void *p,
                              abi_long ret);
---

**replay_hd_transfer**: Called during a replay of a hard drive transfer action

**Callback ID**: PANDA_CB_REPLAY_HD_TRANSFER 
 
**Arguments**:

* `CPUState* env`: pointer to CPUState
* `uint32_t type`: type of transfer (Hd_transfer_type)
* `uint64_t src_addr`: address for src
* `uint64_t dest_addr`: address for dest
* `uint32_t num_bytes`: size of transfer in bytes
      
**Return value**: unused

**Notes**:
In replay only, some kind of data transfer involving hard drive.  NB: We are
neither before nor after, really.  In replay the transfer doesn't really happen.
We are *at* the point at which it happened, really.  Even though the transfer
doesn't happen in replay, useful instrumentations (such as taint analysis) can
still be applied accurately.

**Signature**:

    int (*replay_hd_transfer)(CPUState *env, uint32_t type, uint64_t src_addr,
                              uint64_t dest_addr, uint32_t num_bytes);
---

**replay_before_cpu_physical_mem_rw_ram**: In replay only, we are about to dma
from some qemu buffer to guest memory

**Callback ID**: PANDA_CB_REPLAY_BEFORE_CPU_PHYSICAL_MEM_RW_RAM

**Arguments**:

* `CPUState* env`: pointer to CPUState                   
* `uint32_t is_write`: type of transfer going on (is_write == 1 means IO -> RAM else RAM -> IO)
* `uint64_t src_addr`: src of dma
* `uint64_t dest_addr`: dest of dma
* `uint32_t num_bytes`: size of transfer

**Return value**: unused

**Notes**:
In the current version of QEMU, this appears to be a less commonly used method
of performing DMA with the hard drive device.  For the hard drive, the most
common DMA mechanism can be seen in the PANDA_CB_REPLAY_HD_TRANSFER_TYPE under
type HD_TRANSFER_HD_TO_RAM (and vice versa).  Other devices still appear to use
cpu_physical_memory_rw() though.

**Signature**:

    int (*replay_before_cpu_physical_mem_rw_ram)(
            CPUState *env, uint32_t is_write, uint64_t src_addr, uint64_t dest_addr,
            uint32_t num_bytes);
---

**replay_handle_packet**: TODO: This will be used for network packet replay.

**Callback ID**:   PANDA_CB_REPLAY_HANDLE_PACKET

**Arguments**:

* `CPUState *env`: pointer to CPUState
* `uint8_t *buf`: buffer containing packet data
* `int size`: num bytes in buffer
* `uint8_t direction`: XXX read or write.  not sure which is which.
* `uint64_t old_buf_addr`: XXX this is a mystery

**Signature**:

    int (*replay_handle_packet)(CPUState *env, uint8_t *buf, int size,
                                uint8_t direction, uint64_t old_buf_addr);
---

## Sample Plugin: Syscall Monitor

To make the information in the preceding sections concrete, we will now show how to implement a low-overhead x86 system call monitor as a PANDA plugin. To do so, we will use the `PANDA_CB_INSN_TRANSLATE` and `PANDA_CB_INSN_EXEC` callbacks to create instrumentation that will execute only when the `sysenter` command is executed on x86.

First, we will create a `Makefile` for our plugin, and place it in `panda/qemu/panda_plugins/syscalls`:

```
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

Next, we'll create the main code for the plugin, and put it in `panda/qemu/panda_plugins/syscalls.c`:

```
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

The `init_plugin` function registers the callbacks for instruction translation and execution. Because we are only implementing an x86 callback monitor, we wrap the callback registration in an `#ifdef TARGET_I386`; this means that on other architectures the plugin won't do anything (since no callbacks will be registered). It also opens up a text file that the plugin will use to log the system calls executed by the guest; if opening the file fails, `init_plugin` returns false, which will cause PANDA to unload the plugin immediately.

The `translate_callback` function reads the bytes that make up the instruction that QEMU is about to translate using `cpu_memory_rw_debug`, and and checks to see whether it is a `sysenter` instruction. If so, then it returns `true`, which tells PANDA to insert instrumentation that will cause the `exec_callback` function to be called when the instruction is executed by the guest.

Inside `exec_callback`, we simply log the current program counter (`EIP`) and the contents of the `EAX` register, which is used on both Windows and Linux to hold the system call number.

Finally, in `uninit_plugin`, we simply close the plugin log file.

To make the plugin, we add it to the list of plugins in `panda/qemu/panda_plugins/config.panda`:

	PANDA_PLUGINS = sample taintcap textfinder textprinter syscalls
	
Then run `make` from the base QEMU directory:

```
brendan@laredo3:~/hg/panda/qemu$ make
  CC    /home/brendan/hg/panda/qemu//x86_64-softmmu//panda_plugins/syscalls.o
  PLUGIN  panda_syscalls.so
  CC    /home/brendan/hg/panda/qemu//i386-linux-user//panda_plugins/syscalls.o
  PLUGIN  panda_syscalls.so
  CC    /home/brendan/hg/panda/qemu//arm-linux-user//panda_plugins/syscalls.o
  PLUGIN  panda_syscalls.so
  CC    /home/brendan/hg/panda/qemu//arm-softmmu//panda_plugins/syscalls.o
  PLUGIN  panda_syscalls.so
```

Finally, you can run QEMU with the plugin enabled:

```
x86_64-softmmu/qemu-system-x86_64 -m 1024 -vnc :0 -monitor stdio \
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

The raw system call numbers could also be translated into their names, e.g. by using [Volatility's list of Windows 7 system calls](https://code.google.com/p/volatility/source/browse/trunk/volatility/plugins/overlays/windows/win7_sp01_x86_syscalls.py).
