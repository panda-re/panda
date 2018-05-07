Plugin: taint2
===========

Summary
-------

The `taint2` plugin tracks the flow of data through a running program. One can apply taint labels to some data, follow the flow of labeled data through the program execution, and later query data to find out what labels it has.

`taint2` provides APIs and callbacks for labeling and querying data, and does the work of propagating taint. This means it is not generally useful by itself. To introduce taint into the system, you can use plugins like `file_taint` and `tstringsearch`; to query taint you can use plugins like `tainted_instr`, `dead_data`, or `taint_compute_numbers`.

Note that since this notion of taint supports an arbitrary number of *labels*, the taint on a particular piece of data will typically be a *label set* rather than a single label. For example, if some quantities `a` and `b` have labels `1` and `2` respectively, then an operation such as `c = a + b` will result in `c` being tainted with the label set `{1, 2}`.

PANDA's taint system is implemented by translating TCG code to LLVM and then inserting extra LLVM operations to propagate taint as instructions execute. For more details on how PANDA's taint system works, please see the following papers:

* R. Whelan, T. Leek, D. Kaeli.  Architecture-Independent Dynamic Information Flow Tracking. 22nd International Conference on Compiler Construction (CC), Rome, Italy, March 2013.
* B. Dolan-Gavitt, J. Hodosh, P. Hulin, T. Leek, R. Whelan. Repeatable Reverse Engineering for the Greater Good with PANDA. TR CUCS-023-14.

Note that the `taint2` plugin replaces the original `taint` plugin and is preferred for most use. The main improvements are:

* Speed: `taint2` is much faster (rough estimate: ~10x) due to inlining taint operations into the generated LLVM code rather than accumulating taint operations in a buffer and the processing them after each basic block.
* Memory: many analyses were simply impossible in the original `taint` plugin because the memory requirements were too high. `taint2` should solve this. Note that because it uses a large `mmap`ed area for its shadow memory, you may need to adjust the value of `vm.overcommit_memory` via `sysctl`.
* Interface: the interface to `taint2` is somewhat cleaner, and allows things like tainted branch, tainted instruction, and taint compute number counting to be implemented as separate plugins.

Arguments
---------

* `no_tp`: boolean. Whether to taint the result of dereferencing a pointer that has been tainted.
* `inline`: boolean. Whether taint operations should be carried out in line with generated code, or through a function call.
* `binary`: boolean. Whether to use binary taint (i.e., data is tainted or not tainted, rather than supporting arbitrary numbers of labels).
* `word`: boolean. Whether to track taint at word-level (i.e., 4 bytes on a 32-bit architecture) as opposed to byte-level. Can provide a performance improvement at the cost of reduced precision.
* `opt`:  boolean. Whether to run an optimization pass on the instrumented LLVM code.

Dependencies
------------

The `taint2` plugin uses `callstack_instr` to get the callstack when writing entries to the pandalog. `taint2` will automatically load the `callstack_instr` plugin so there is usually no need to load it explicitly.

APIs and Callbacks
------------------

Name: **on_branch2**

Signature: `typedef void (*on_branch2_t) (Addr addr, uint64_t size)`

Description: Called when a branch that depends on tainted data is encountered. The `Addr` parameter (a union of the various types of memory that can be tracked by the taint system) provides the address of the data that the tainted branch depends on.

Name: **on_taint_change**

Signature: `typedef void (*on_taint_change_t) (Addr, uint64_t)`

Description: Called whenever the state of taint changes; i.e. when taint is propagated. The `Addr` of the newly tainted data is provided, as well as its size.

`taint2` also provides the following APIs:

    // turns on taint
    void taint2_enable_taint(void);

    // returns 1 if taint is on
    int taint2_enabled(void);

    // label this phys addr in memory with label l
    void taint2_label_ram(uint64_t pa, uint32_t l);
    
    // add label l to this phys addr in memory. any previous labels applied to 
    // this address are not removed.
    void taint2_label_ram_additive(uint64_t pa, uint32_t l);

    // add label l to this register. any previous labels applied to this 
    // register are not removed.
    void taint2_label_reg_additive(int reg_num, int offset, uint32_t l);

    // query fns return 0 if untainted, else cardinality of taint set
    uint32_t taint2_query(Addr a);
    uint32_t taint2_query_ram(uint64_t pa);
    uint32_t taint2_query_reg(int reg_num, int offset);
    uint32_t taint2_query_llvm(int reg_num, int offset);

    // query set fns writes taint set contents to the specified array. the
    // size of the array must be >= the cardianlity of the taint set.
    void taint2_query_set(Addr a, uint32_t *out);
    void taint2_query_set_ram(uint64_t pa, uint32_t *out);
    void taint2_query_set_reg(int reg_num, int offset, uint32_t *out);

    // returns cardinality and the taint set.
    // reallocates and updates buffer size as needed.
    uint32_t taint2_query_set_a(Addr a, uint32_t **out, uint32_t *outsz);

    // returns taint compute number associated with addr
    uint32_t taint2_query_tcn(Addr a);
    uint32_t taint2_query_tcn_ram(uint64_t pa);
    uint32_t taint2_query_tcn_reg(int reg_num, int offset);
    uint32_t taint2_query_tcn_llvm(int reg_num, int offset);

    // Returns a mask indicating which bits are attacker-controlled (derived
    // reversibly from input).
    uint64_t taint2_query_cb_mask(Addr a, uint8_t size);

    // delete taint from this phys addr
    void taint2_delete_ram(uint64_t pa) ;

    // print out a labelset.
    void taint2_labelset_spit(LabelSetP ls) ; 

    // apply this fn to each of the labels associated with this pa
    // fn should return 0 to continue iteration
    void taint2_labelset_ram_iter(uint64_t pa, int (*app)(uint32_t el, void *stuff1), void *stuff2);

    // ditto, but a machine register
    // you should be able to use R_EAX, etc as reg_num
    // offset is byte offset withing that reg.
    void taint2_labelset_reg_iter(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2);

    // ditto, but for llvm regs.  dunno where you are getting that number
    void taint2_labelset_llvm_iter(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2);

    // ditto, but someone handed you the ls, e.g. a callback like tainted branch
    void taint2_labelset_iter(LabelSetP ls,  int (*app)(uint32_t el, void *stuff1), void *stuff2) ;

    // returns set of so-far applied labels as a sorted array
    // NB: This allocates memory. Caller frees.
    uint32_t *taint2_labels_applied(void);

    // just tells how big that labels_applied set will be
    uint32_t taint2_num_labels_applied(void);

    // Track whether taint state actually changed during a BB
    void taint2_track_taint_state(void);

The `taint2` plugin also supports logging taint in pandalog format:

    // queries taint on this virtual addr and, if any taint there,
    // writes an entry to pandalog with lots of stuff like
    // label set, taint compute #, call stack
    // offset is needed since this is likely a query in the middle of an extent (of 4, 8, or more bytes)
    Panda__TaintQuery *taint2_query_pandalog (Addr addr, uint32_t offset) ;

    // used to free memory associated with that struct
    void pandalog_taint_query_free(Panda__TaintQuery *tq);


Example
-------

To taint data from a file named `foo.dat` on Linux and then find out what branches depend on data from that file, placing output into the pandalog `foo.plog`:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo -panda osi \
        -panda osi_linux:kconf_group=debian-3.2.63-i686 \
        -panda syscalls2:profile=linux_x86 \
        -panda file_taint:filename=foo.dat \
        -panda tainted_branch \
        -pandalog foo.plog

Note that the `taint2` plugin is not explicitly listed here because it is automatically loaded by the `file_taint` plugin. If you wanted to pass custom options to `taint2`, such as disabling tainted pointers, you could instead do:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo -panda osi \
        -panda osi_linux:kconf_group=debian-3.2.63-i686 \
        -panda syscalls2:profile=linux_x86 \
        -panda taint2:no_tp=y \
        -panda file_taint:filename=foo.dat \
        -panda tainted_branch \
        -pandalog foo.plog
