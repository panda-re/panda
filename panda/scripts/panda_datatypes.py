from enum import Enum
from ctypes import *

class cb_types(Enum):
    PANDA_CB_BEFORE_BLOCK_TRANSLATE = 0 # Before translating each basic block
    PANDA_CB_AFTER_BLOCK_TRANSLATE = 1  # After translating each basic block
    PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT = 2 # Before executing each basic
                                               # block (with option to
                                               # invalidate, may trigger
                                               # retranslation)
    PANDA_CB_BEFORE_BLOCK_EXEC = 3 # Before executing each basic block
    PANDA_CB_AFTER_BLOCK_EXEC = 4  # After executing each basic block
    PANDA_CB_INSN_TRANSLATE = 5    # Before an insn is translated
    PANDA_CB_INSN_EXEC = 6         # Before an insn is executed
    PANDA_CB_AFTER_INSN_TRANSLATE = 7  # After an insn is translated
    PANDA_CB_AFTER_INSN_EXEC = 8   # After an insn is executed

    PANDA_CB_VIRT_MEM_BEFORE_READ = 9
    PANDA_CB_VIRT_MEM_BEFORE_WRITE = 10
    PANDA_CB_PHYS_MEM_BEFORE_READ = 11
    PANDA_CB_PHYS_MEM_BEFORE_WRITE = 12

    PANDA_CB_VIRT_MEM_AFTER_READ = 13
    PANDA_CB_VIRT_MEM_AFTER_WRITE = 14
    PANDA_CB_PHYS_MEM_AFTER_READ = 15
    PANDA_CB_PHYS_MEM_AFTER_WRITE =16

    PANDA_CB_HD_READ = 17              # Each HDD read
    PANDA_CB_HD_WRITE = 18             # Each HDD write
    PANDA_CB_GUEST_HYPERCALL = 19      # Hypercall from the guest (e.g. CPUID)
    PANDA_CB_MONITOR = 20              # Monitor callback
    PANDA_CB_CPU_RESTORE_STATE = 21    # In cpu_restore_state() (fault/exception)
    PANDA_CB_BEFORE_REPLAY_LOADVM = 22 # at start of replay, before loadvm
    PANDA_CB_ASID_CHANGED = 23         # When CPU asid (address space identifier) changes
    PANDA_CB_REPLAY_HD_TRANSFER = 24    # in replay, hd transfer
    PANDA_CB_REPLAY_NET_TRANSFER = 25   # in replay, transfers within network card
                                        # (currently only E1000)
    PANDA_CB_REPLAY_SERIAL_RECEIVE = 26 # in replay, right after data is pushed
                                        # into the serial RX FIFO
    PANDA_CB_REPLAY_SERIAL_READ = 27  # in replay, right after a value is read from
                                      # the serial RX FIFO.
    PANDA_CB_REPLAY_SERIAL_SEND = 28  # in replay, right after data is popped from
                                      # the serial TX FIFO
    PANDA_CB_REPLAY_SERIAL_WRITE = 29 # in replay, right after data is pushed into
                                      # the serial TX FIFO.
    PANDA_CB_REPLAY_BEFORE_DMA = 30   # in replay, just before RAM case of
                                      # cpu_physical_mem_rw
    PANDA_CB_REPLAY_AFTER_DMA = 31    # in replay, just after RAM case of
                                      # cpu_physical_mem_rw
    PANDA_CB_REPLAY_HANDLE_PACKET = 32 # in replay, packet in / out
    PANDA_CB_AFTER_MACHINE_INIT = 33   # Right after the machine is initialized,
                                       # before any code runs

    PANDA_CB_TOP_LOOP = 34 # at top of loop that manages emulation.  good place to
                           # take a snapshot

    PANDA_CB_LAST = 35

class panda_cb(Union):
    _field_ = [("before_block_exec_invalidate_opt", c_void_p),  
                            # bool (*before_block_exec_invalidate_opt)(CPUState *env, TranslationBlock *tb);     
                                    # Callback ID: PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT

                                    #        before_block_exec_invalidate_opt: called before execution of every basic
                                    #        block, with the option to invalidate the TB

                                    #        Arguments:
                                    #         CPUState *env: the current CPU state
                                    #         TranslationBlock *tb: the TB we are about to execute

                                    #        Return value:
                                    #         true if we should invalidate the current translation block
                                    #         and retranslate, false otherwise
                ("before_block_exec", c_void_p),
                            # int (*before_block_exec)(CPUState *env, TranslationBlock *tb);
                                    # Callback ID: PANDA_CB_BEFORE_BLOCK_EXEC

                                    #    before_block_exec: called before execution of every basic block

                                    #    Arguments:
                                    #     CPUState *env: the current CPU state
                                    #     TranslationBlock *tb: the TB we are about to execute

                                    #    Return value:
                                    #     unused
                ("after_block_exec", c_void_p),
                            # int (*after_block_exec)(CPUState *env, TranslationBlock *tb);
                                    # Callback ID: PANDA_CB_AFTER_BLOCK_EXEC

                                    #    after_block_exec: called after execution of every basic block

                                    #    Arguments:
                                    #     CPUState *env: the current CPU state
                                    #     TranslationBlock *tb: the TB we just executed
                                    #     TranslationBlock *next_tb: the TB we will execute next (may be NULL)

                                    #    Return value:
                                    #     unused
                ("before_block_translate", c_void_p),
                            # int (*before_block_translate)(CPUState *env, target_ulong pc);
                                    # Callback ID: PANDA_CB_BEFORE_BLOCK_TRANSLATE
                                    #   before_block_translate: called before translation of each basic block

                                    #   Arguments:
                                    #    CPUState *env: the current CPU state
                                    #    target_ulong pc: the guest PC we are about to translate

                                    #   Return value:
                                    #    unused
                ("after_block_translate", c_void_p),
                            # int (*after_block_translate)(CPUState *env, TranslationBlock *tb);
                                    # Callback ID: PANDA_CB_AFTER_BLOCK_TRANSLATE

                                    #   after_block_translate: called after the translation of each basic block

                                    #   Arguments:
                                    #    CPUState *env: the current CPU state
                                    #    TranslationBlock *tb: the TB we just translated

                                    #   Return value:
                                    #    unused

                                    #   Notes:
                                    #    This is a good place to perform extra passes over the generated
                                    #    code (particularly by manipulating the LLVM code)
                                    #    FIXME: How would this actually work? By this point the out ASM
                                    #        has already been generated. Modify the IR and then regenerate?
                ("insn_translate", c_void_p),
                            # bool (*insn_translate)(CPUState *env, target_ulong pc);
                                    # Callback ID: PANDA_CB_INSN_TRANSLATE

                                    #    insn_translate: called before the translation of each instruction

                                    #    Arguments:
                                    #     CPUState *env: the current CPU state
                                    #     target_ulong pc: the guest PC we are about to translate

                                    #    Return value:
                                    #     true if PANDA should insert instrumentation into the generated code,
                                    #     false otherwise

                                    #    Notes:
                                    #     This allows a plugin writer to instrument only a small number of
                                    #     instructions, avoiding the performance hit of instrumenting everything.
                                    #     If you do want to instrument every single instruction, just return
                                    #     true. See the documentation for PANDA_CB_INSN_EXEC for more detail.
                ("insn_exec", c_void_p),
                            # int (*insn_exec)(CPUState *env, target_ulong pc);
                                    # Callback ID: PANDA_CB_INSN_EXEC

                                    #    insn_exec: called before execution of any instruction identified
                                    #     by the PANDA_CB_INSN_TRANSLATE callback

                                    #    Arguments:
                                    #     CPUState *env: the current CPU state
                                    #     target_ulong pc: the guest PC we are about to execute

                                    #    Return value:
                                    #     unused

                                    #    Notes:
                                    #     This instrumentation is implemented by generating a call to a
                                    #     helper function just before the instruction itself is generated.
                                    #     This is fairly expensive, which is why it's only enabled via
                                    #     the PANDA_CB_INSN_TRANSLATE callback.
                ("after_insn_translate", c_void_p),
                            # bool (*after_insn_translate)(CPUState *env, target_ulong pc);

                                    # Callback ID: PANDA_CB_AFTER_INSN_TRANSLATE
                                
                                    #    after_insn_translate: called after the translation of each instruction
                                
                                    #    Arguments:
                                    #     CPUState *env: the current CPU state
                                    #     target_ulong pc: the next guest PC we've translated

                                    #    Return value:
                                    #     true if PANDA should insert instrumentation into the generated code,
                                    #     false otherwise

                                    #    Notes:
                                    #     See `insn_translate`, callbacks are registered via PANDA_CB_AFTER_INSN_EXEC 
                ("after_insn_exec", c_void_p),
                            # int (*after_insn_exec)(CPUState *env, target_ulong pc);
                                    # Callback ID: PANDA_CB_AFTER_INSN_EXEC

                                    #    after_insn_exec: called after execution of an instruction identified
                                    #     by the PANDA_CB_AFTER_INSN_TRANSLATE callback

                                    #    Arguments:
                                    #     CPUState *env: the current CPU state
                                    #     target_ulong pc: the next guest PC already executed

                                    #    Return value:
                                    #     unused

                                    #    Notes:
                                    #     See `insn_exec`. Enabled via the PANDA_CB_AFTER_INSN_TRANSLATE callback.
                ("guest_hypercall", c_void_p),
                            # int (*guest_hypercall)(CPUState *env);
                                    # Callback ID: PANDA_CB_GUEST_HYPERCALL

                                    #    guest_hypercall: called when a program inside the guest makes a
                                    #     hypercall to pass information from inside the guest to a plugin

                                    #    Arguments:
                                    #     CPUState *env: the current CPU state

                                    #    Return value:
                                    #     unused

                                    #    Notes:
                                    #     On x86, this is called whenever CPUID is executed. Plugins then
                                    #     check for magic values in the registers to determine if it really
                                    #     is a guest hypercall. Parameters can be passed in other registers.

                                    #     S2E accomplishes this by using a (currently) undefined opcode. We
                                    #     have instead opted to use an existing instruction to make development
                                    #     easier (we can use inline asm rather than defining the raw bytes).

                                    #     AMD's SVM and Intel's VT define hypercalls, but they are privileged
                                    #     instructinos, meaning the guest must be in ring 0 to execute them.
                ("monitor", c_void_p),
                            # int (*monitor)(Monitor *mon, const char *cmd);
                                    # Callback ID: PANDA_CB_MONITOR

                                    #    monitor: called when someone uses the plugin_cmd monitor command

                                    #    Arguments:
                                    #     Monitor *mon: a pointer to the Monitor
                                    #     const char *cmd: the command string passed to plugin_cmd

                                    #    Return value:
                                    #     unused

                                    #    Notes:
                                    #     The command is passed as a single string. No parsing is performed
                                    #     on the string before it is passed to the plugin, so each plugin
                                    #     must parse the string as it deems appropriate (e.g. by using strtok
                                    #     and getopt) to do more complex option processing.

                                    #     It is recommended that each plugin implementing this callback respond
                                    #     to the "help" message by listing the commands supported by the plugin.

                                    #     Note that every loaded plugin will have the opportunity to respond to
                                    #     each plugin_cmd; thus it is a good idea to ensure that your plugin's
                                    #     monitor commands are uniquely named, e.g. by using the plugin name
                                    #     as a prefix ("sample_do_foo" rather than "do_foo").
                ("virt_mem_before_read", c_void_p),
                            # int (*virt_mem_before_read)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size);
                                    # Callback ID: PANDA_CB_VIRT_MEM_BEFORE_READ

                                    #    virt_mem_before_read: called before memory is read

                                    #    Arguments:
                                    #     CPUState *env: the current CPU state
                                    #     target_ulong pc: the guest PC doing the read
                                    #     target_ulong addr: the (virtual) address being read
                                    #     target_ulong size: the size of the read

                                    #    Return value:
                                    #     unused
                ("virt_mem_before_write", c_void_p),
                            # int (*virt_mem_before_write)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
                                    # Callback ID: PANDA_CB_VIRT_MEM_BEFORE_WRITE

                                    #    virt_mem_before_write: called before memory is written
                                    #    [exists]

                                    #    Arguments:
                                    #     CPUState *env: the current CPU state
                                    #     target_ulong pc: the guest PC doing the write
                                    #     target_ulong addr: the (virtual) address being written
                                    #     target_ulong size: the size of the write
                                    #     void *buf: pointer to the data that is to be written

                                    #    Return value:
                                    #     unused
                ("phys_mem_before_read", c_void_p),
                            # int (*phys_mem_before_read)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size);
                                    # Callback ID: PANDA_CB_PHYS_MEM_BEFORE_READ

                                    #    phys_mem_before_read: called after memory is read
                                    #    [new]

                                    #    Arguments:
                                    #     CPUState *env: the current CPU state
                                    #     target_ulong pc: the guest PC doing the read
                                    #     target_ulong addr: the (physical) address being read
                                    #     target_ulong size: the size of the read

                                    #    Return value:
                                    #     unused
                ("phys_mem_before_write", c_void_p),
                            # int (*phys_mem_before_write)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
                                    # Callback ID: PANDA_CB_PHYS_MEM_BEFORE_WRITE

                                    #    phys_mem_write: called before memory is written
                                    #    [exists]

                                    #    Arguments:
                                    #     CPUState *env: the current CPU state
                                    #     target_ulong pc: the guest PC doing the write
                                    #     target_ulong addr: the (physical) address being written
                                    #     target_ulong size: the size of the write
                                    #     void *buf: pointer to the data that is to be written

                                    #    Return value:
                                    #     unused
                ("virt_mem_after_read", c_void_p),
                            # int (*virt_mem_after_read)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
                                    # Callback ID: PANDA_CB_VIRT_MEM_AFTER_READ

                                    #    virt_mem_after_read: called after memory is read
                                    #    [exists]
                                
                                    #    Arguments:
                                    #     CPUState *env: the current CPU state
                                    #     target_ulong pc: the guest PC doing the read
                                    #     target_ulong addr: the (virtual) address being read
                                    #     target_ulong size: the size of the read
                                    #     void *buf: pointer to data just read

                                    #    Return value:
                                    #     unused
            ("virt_mem_after_write", c_void_p),
                            # int (*virt_mem_after_write)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
                                    # Callback ID: PANDA_CB_VIRT_MEM_AFTER_WRITE

                                    #    virt_mem_after_write: called after memory is written
                                    #    [new]

                                    #    Arguments:
                                    #     CPUState *env: the current CPU state
                                    #     target_ulong pc: the guest PC doing the write
                                    #     target_ulong addr: the (virtual) address being written
                                    #     target_ulong size: the size of the write
                                    #     void *buf: pointer to the data that was written

                                    #    Return value:
                                    #     unused
            ("phys_mem_after_read", c_void_p),
                            # int (*phys_mem_after_read)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
                                    # Callback ID: PANDA_CB_PHYS_MEM_AFTER_READ

                                    #    phys_mem_after_read: called after memory is read
                                    #    [exists]

                                    #    Arguments:
                                    #     CPUState *env: the current CPU state
                                    #     target_ulong pc: the guest PC doing the read
                                    #     target_ulong addr: the (physical) address being read
                                    #     target_ulong size: the size of the read
                                    #     void *buf: pointer to data just read

                                    #    Return value:
                                    #     unused
            ("phys_mem_after_write", c_void_p),
                            # int (*phys_mem_after_write)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
                                    # Callback ID: PANDA_CB_PHYS_MEM_AFTER_WRITE

                                    #    phys_mem_write: called after memory is written
                                    #    [new]

                                    #    Arguments:
                                    #     CPUState *env: the current CPU state
                                    #     target_ulong pc: the guest PC doing the write
                                    #     target_ulong addr: the (physical) address being written
                                    #     target_ulong size: the size of the write
                                    #     void *buf: pointer to the data that was written

                                    #    Return value:
                                    #     unused
            ("cb_cpu_restore_state", c_void_p),
                            # int (*cb_cpu_restore_state)(CPUState *env, TranslationBlock *tb);
                                    # Callback ID: PANDA_CB_CPU_RESTORE_STATE

                                    #    cb_cpu_restore_state: called inside of cpu_restore_state(), when there is
                                    #     a CPU fault/exception

                                    #    Arguments:
                                    #     CPUState *env: the current CPU state
                                    #     TranslationBlock *tb: the current translation block

                                    #    Return value:
                                    #     unused
            ("before_loadvm", c_void_p),
                            # int (*before_loadvm)(void);
                                    # Callback ID: PANDA_CB_BEFORE_LOADVM

                                    #    before_loadvm: called at start of replay, before loadvm is called.
                                    #     This allows us to hook devices' loadvm handlers.
                                    #     Remember to unregister the existing handler for the device first.
                                    #     See the example in the sample plugin.
                                    #     Arguments:

                                    #     Return value:
                                    #      unused
            ("asid_changed", c_void_p),
                            # int (*asid_changed)(CPUState *env, target_ulong oldval, target_ulong newval);
                                    # Callback ID: PANDA_CB_ASID_CHANGED

                                    #    asid_changed: Called when asid changes.

                                    #    Arguments:
                                    #     CPUState* env: pointer to CPUState
                                    #     target_ulong oldval: old asid value
                                    #     target_ulong newval: new asid value

                                    #    Return value:
                                    #     unused
            ("replay_hd_transfer", c_void_p),
                            # int (*replay_hd_transfer)(CPUState *env, uint32_t type, uint64_t src_addr, uint64_t dest_addr, uint32_t num_bytes);
                                    # Callback ID:     PANDA_CB_REPLAY_HD_TRANSFER,

                                    #    In replay only, some kind of data transfer involving hard drive.
                                    #    NB: We are neither before nor after, really.
                                    #    In replay the transfer doesn't really happen.
                                    #    We are *at* the point at which it happened, really.

                                    #    Arguments:
                                    #     CPUState* env: pointer to CPUState
                                    #     uint32_t type:        type of transfer  (Hd_transfer_type)
                                    #     uint64_t src_addr:    address for src
                                    #     uint64_t dest_addr:   address for dest
                                    #     uint32_t num_bytes:   size of transfer in bytes

                                    #    Return value:
                                    #     unused
            ("replay_before_dma", c_void_p),
                            # int (*replay_before_dma)(CPUState *env, uint32_t is_write, uint8_t* src_addr, uint64_t dest_addr, uint32_t num_bytes);
                                    # Callback ID:     PANDA_CB_REPLAY_BEFORE_DMA,

                                    #    In replay only, we are about to dma between qemu buffer and guest memory

                                    #    Arguments:
                                    #     CPUState* env:       pointer to CPUState
                                    #     uint32_t is_write:   type of transfer going on    (is_write == 1 means IO -> RAM else RAM -> IO)
                                    #     uint8_t* buf         the QEMU device's buffer in QEMU's virtual memory
                                    #     uint64_t paddr       "physical" address of guest RAM
                                    #     uint32_t num_bytes:  size of transfer
            ("replay_after_dma", c_void_p),
                            # int (*replay_after_dma)(CPUState *env, uint32_t is_write, uint8_t* src_addr, uint64_t dest_addr, uint32_t num_bytes);
                                        # Callback ID:     PANDA_CB_REPLAY_AFTER_DMA,

                                        #    In replay only, we are about to dma between qemu buffer and guest memory

                                        #    Arguments:
                                        #     CPUState* env:       pointer to CPUState
                                        #     uint32_t is_write:   type of transfer going on    (is_write == 1 means IO -> RAM else RAM -> IO)
                                        #     uint8_t* buf         the QEMU device's buffer in QEMU's virtual memory
                                        #     uint64_t paddr       "physical" address of guest RAM
                                        #     uint32_t num_bytes:  size of transfer
            ("replay_handle_packet", c_void_p),
                            # int (*replay_handle_packet)(CPUState *env, uint8_t *buf, int size, uint8_t direction, uint64_t old_buf_addr);
                                        # Callback ID:   PANDA_CB_REPLAY_HANDLE_PACKET,

                                        #    In replay only, we have a packet (incoming / outgoing) in hand.

                                        #    Arguments:
                                        #     CPUState *env          pointer to CPUState
                                        #     uint8_t *buf           buffer containing packet data
                                        #     int size               num bytes in buffer
                                        #     uint8_t direction      XXX read or write.  not sure which is which.
                                        #     uint64_t old_buf_addr  XXX this is a mystery
            ("replay_net_transfer", c_void_p),
                            # int (*replay_net_transfer)(CPUState *env, uint32_t type, uint64_t src_addr, uint64_t dest_addr, uint32_t num_bytes);
    # Callback ID:     PANDA_CB_REPLAY_NET_TRANSFER,

                                        #    In replay only, some kind of data transfer within the network card
                                        #    (currently, only the E1000 is supported).  NB: We are neither before nor
                                        #    after, really.  In replay the transfer doesn't really happen.  We are
                                        #    *at* the point at which it happened, really.

                                        #    Arguments:
                                        #     CPUState* env:        pointer to CPUState
                                        #     uint32_t type:        type of transfer  (Net_transfer_type)
                                        #     uint64_t src_addr:    address for src
                                        #     uint64_t dest_addr:   address for dest
                                        #     uint32_t num_bytes:   size of transfer in bytes

                                        #    Return value:
                                        #     unused
             ("replay_serial_receive", c_void_p),
                            # int (*replay_serial_receive)(CPUState *env, uint64_t fifo_addr, uint8_t value);
                                        # Callback ID:     PANDA_CB_REPLAY_SERIAL_RECEIVE,

                                        #    In replay only, called when a byte is received on the serial port.

                                        #    Arguments:
                                        #     CPUState* env:        pointer to CPUState
                                        #     uint64_t fifo_addr:   address of the data within the fifo
                                        #     uint8_t value:        value received
                                    
                                        #    Return value:
                                        #     unused
            ("replay_serial_read", c_void_p),
                            # int (*replay_serial_read)(CPUState *env, uint64_t fifo_addr, uint32_t port_addr, uint8_t value);
                                        # Callback ID:     PANDA_CB_REPLAY_SERIAL_READ,

                                        #    In replay only, called when a byte read from the serial RX FIFO

                                        #    Arguments:
                                        #     CPUState* env:        pointer to CPUState
                                        #     uint64_t fifo_addr:   address of the data within the fifo (source)
                                        #     uint32_t port_addr:   address of the IO port where data is being
                                        #                           read (destination)
                                        #     uint8_t value:        value read

                                        #    Return value:
                                        #     unused
             ("replay_serial_send", c_void_p),
                            # int (*replay_serial_send)(CPUState *env, uint64_t fifo_addr, uint8_t value);
                                        # Callback ID:     PANDA_CB_REPLAY_SERIAL_SEND,

                                        #    In replay only, called when a byte is sent on the serial port.

                                        #    Arguments:
                                        #     CPUState* env:        pointer to CPUState
                                        #     uint64_t fifo_addr:   address of the data within the fifo
                                        #     uint8_t value:        value received

                                        #    Return value:
                                        #     unused
            ("replay_serial_write", c_void_p),
                            # int (*replay_serial_write)(CPUState *env, uint64_t fifo_addr, uint32_t port_addr, uint8_t value);
                                        # Callback ID:     PANDA_CB_REPLAY_SERIAL_WRITE,

                                        #    In replay only, called when a byte written to the serial TX FIFO

                                        #    Arguments:
                                        #     CPUState* env:        pointer to CPUState
                                        #     uint64_t fifo_addr:   address of the data within the fifo (source)
                                        #     uint32_t port_addr:   address of the IO port where data is being
                                        #                           read (destination)
                                        #     uint8_t value:        value read

                                        #    Return value:
                                        #     unused
            ("after_machine_init", c_void_p),
                            # void (*after_machine_init)(CPUState *env);
    # Callback ID:     PANDA_CB_AFTER_MACHINE_INIT

                                        #    after_machine_init: Called right after the machine has been
                                        #    initialized, but before any guest code runs.

                                        #    Arguments:
                                        #     void *cpu_env: pointer to CPUState

                                        #    Return value:
                                        #     unused

                                        #    Notes:
                                        #     This callback allows initialization of components that need access
                                        #    to the RAM, CPU object, etc. E.g. for the taint2 plugin, this is the
                                        #    appropriate place to call taint2_enable_taint().
            ("top_loop", c_void_p),
                            # void (*top_loop)(CPUState *env);
                                        # Callback ID:     PANDA_CB_TOP_LOOP
                                    
                                        #    top_loop: Called at the top of the loop that manages emulation.

                                        #    Arguments:
                                        #     void *cpu_env: pointer to CPUState

                                        #    Return value:
                                        #     unused
            ("cbaddr", c_void_p)]
                            # void (* cbaddr)(void);
                                        # Dummy union member.

                                        #    This union only contains function pointers.
                                        #    Using the cbaddr member one can compare if two union instances
                                        #    point to the same callback function. In principle, any other
                                        #    member could be used instead.
                                        #    However, cbaddr provides neutral semantics for the comparisson.


class PandaState(Enum):
    UNINT = 1
    INIT_DONE = 2
    IN_RECORD = 3
    IN_REPLAY = 4   
    

#for val in cb_types:
#    print(val)

#cb = panda_cb()
#cb.cbaddr = 3
#print (cb.cbaddr)
