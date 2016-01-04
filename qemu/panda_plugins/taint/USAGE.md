Plugin: taint
===========

Summary
-------

The `taint` plugin tracks the flow of data through a running program. One can apply taint labels to some data, follow the flow of labeled data through the program execution, and later query data to find out what labels it has. It is also possible to find out what instructions handle tainted data, and measure how much computation has been done on some data.

Note that since this notion of taint supports an arbitrary number of *labels*, the taint on a particular piece of data will typically be a *label set* rather than a single label. For example, if some quantities `a` and `b` have labels `1` and `2` respectively, then an operation such as `c = a + b` will result in `c` being tainted with the label set `{1, 2}`.

For more details on how PANDA's taint system works, please see the following papers:

* R. Whelan, T. Leek, D. Kaeli.  Architecture-Independent Dynamic Information Flow Tracking. 22nd International Conference on Compiler Construction (CC), Rome, Italy, March 2013.
* B. Dolan-Gavitt, J. Hodosh, P. Hulin, T. Leek, R. Whelan.  Repeatable Reverse Engineering for the Greater Good with PANDA. TR CUCS-023-14.

**Warning**: The `taint` plugin is **deprecated** in favor of `taint2`. However, despite being slower and more memory intensive, it still has one advantage over `taint2`: `taint` supports tracking taint across hard drive reads and writes and automatically labeling and querying network data. If the analysis you're doing needs that, then you should still use `taint` (or better, add support for hard drive and network taint to `taint2` and submit a pull request!).

Arguments
---------

* `max_taintset_card`: uint32, defaults to unlimited. The maximum size a label set can reach before we will stop tracking taint on it. The intuition here is that some operations (e.g., cryptographic functions) combine lots of tainted data in their computation, and that the results may not be interesting since there will no longer be a clear correspondence with some particular piece of input data.
* `max_taintset_compute_number`: uint32, defaults to unlimited. The maximum 
* `compute_is_delete`: boolean.
* `label_incoming_network`: boolean.
* `query_outgoing_network`: boolean.
* `no_tainted_pointer`: boolean.
* `label_mode`: string, defaults to `byte`. One of `binary` or `byte`.
* `tainted_instructions`: boolean.

Dependencies
------------

None.

APIs and Callbacks
------------------

The `taint` plugin provides the following callbacks:

`typedef void (*on_load_t) (uint64_t tp_pc, uint64_t addr)`
`typedef void (*on_store_t) (uint64_t tp_pc, uint64_t addr)`
`typedef void (*on_branch_t) (uint64_t pc, int reg_num)`
`typedef void (*before_execute_taint_ops_t) (void)`
`typedef void (*after_execute_taint_ops_t) (void)`
`typedef void (*on_tainted_instruction_t) (Shad *shad)`


The `taint` plugin provides the following APIs:

    // turns on taint
    void taint_enable_taint(void);

    // returns 1 if taint is on
    int taint_enabled(void);

    // label this phys addr in memory with label l
    void taint_label_ram(uint64_t pa, uint32_t l);

    // if phys addr pa is untainted, return 0.
    // else returns label set cardinality 
    uint32_t taint_query_ram(uint64_t pa);

    // Return one label; ~0 if not labeled.
    uint32_t taint_pick_label(uint64_t pa);

    // if offset of reg is untainted, ...
    uint32_t taint_query_reg(int reg_num, int offset);

    // if offset of llvm reg is untainted, ...
    uint32_t taint_query_llvm(int reg_num, int offset);

    // Print the labels on a register
    void taint_spit_reg(int reg_num, int offset);

    // Print the labels on an llvm register
    void taint_spit_llvm(int reg_num, int offset);

    // delete taint from this phys addr
    void taint_delete_ram(uint64_t pa) ;

    // returns number of tainted addrs in ram
    uint32_t taint_occ_ram(void);

    // returns the max ls type (taint compute #) observed so far
    uint32_t taint_max_obs_ls_type(void) ;

    // returns the ls type (taint compute #) for the given llvm register
    uint32_t taint_get_ls_type_llvm(int reg_num, int offset);

    // clears the flag indicating tainted computation happened
    void taint_clear_tainted_computation_happened(void);

    // reads the flag indicating tainted computation happened
    int taint_tainted_computation_happened(void);

    // clears the flag indicating taint state has changed
    void taint_clear_taint_state_changed(void);

    // returns the flag
    int taint_taint_state_changed(void);

    // clears the flag indicating taint state has been read
    void taint_clear_taint_state_read(void);

    // returns the flag
    int taint_taint_state_read(void);

    // Clear all taint from the shadow memory (by reinstantiating it)
    void taint_clear_shadow_memory(void);

    // apply this fn to each of the labels associated with this pa
    // fn should return 0 to continue iteration
    void taint_labelset_ram_iter(uint64_t pa, int (*app)(uint32_t el, void *stuff1), void *stuff2);

    // ditto, but a machine register
    // you should be able to use R_EAX, etc as reg_num
    // offset is byte offset withing that reg.
    void taint_labelset_reg_iter(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2);

    // ditto, but for llvm regs.  dunno where you are getting that number
    void taint_labelset_llvm_iter(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2);

    // ditto, but someone handed you the ls, e.g. a callback like tainted branch
    void taint_labelset_iter(LabelSetP ls,  int (*app)(uint32_t el, void *stuff1), void *stuff2) ;

Example
-------

FIXME
