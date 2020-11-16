
Plugin: func_stats
===========

Summary
-------

The `func_stats` plugin produces a report of synthetic information of function calls in a replay--including memory access information. Each line in the `func_stats` report represents a record of a function call. The `entrypoint` is basically the identifier, and if more than one entry is found with the same `entrypoint`, then that is how many this function got called. 

The plugin logs N calls to the functions passing the asids to examine, and it operates in user mode. Moreover, this plugin is quite useful to plot and analyze Control Flow Graphs and Data Flow Graphs. Additionally, it helps to detect, identify and classify cryptographic functions. The logged information include the count of basic blocks and number of functions, as well as the number of times they were executed. Along with, the count of arithmetic/binary instructions, data buffer statistics (including size and Shannon's entropy). Last but not least, it also reports the same type of information but from the lifted code (LLVM) featuring LLVM visitors--not only via disassembling the basic blocks. In fact, if you use the `scripts/find_drm.py` in combination with this plugin, you will find matching results by caller (yet more verbose), and much more.

The plugin produces a JSON file (named `func_stats`); in which, each line is a JSON object that looks like the following:
    
    {"asid":"8ca0000","caller":"b7eb3364","callstack":["b7fe388f","b7ff1029","b7ff0f0c","b7eb3364"],"distinct_blocks":1,"entrypoint":"b7eb3364","functionstack":["b7ff0fb0","b7ff0e90","b7eb3358","b7eb3364"],"insn_arith":1,"insn_movs":1,"insn_total":5,"instr_count":120206427,"llvm_bb":3,"llvm_fn":1,"llvm_insn_alloc":1,"llvm_insn_arit":17,"llvm_insn_call":3,"llvm_insn_intrinsic":0,"llvm_insn_load":5,"llvm_insn_store":20,"llvm_insn_tot":23,"llvm_modules":0,"maxexecs":1,"maxexecs_addr":"b7eb3358","nreads":0,"nwrites":0,"pc":"b7eb335f","reads":[],"sumexecs":1,"writes":[]}
    
Note that, in hex reporting mode, addresses are reported in the simplest form. E.g., "asid":"8ca0000".

If you use the following command to dump the assembly in a given replay:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo -d in_asm,op,int,rr > asm.out 2>&113.
    
Then you search by the `pc` in the instructions, you will find the following (for the above example record):

    0x00000000b7eb3358:  push   ebp
	0x00000000b7eb3359:  mov    ebp,esp
	0x00000000b7eb335b:  push   ebx
	0x00000000b7eb335c:  sub    esp,0x4
	0x00000000b7eb335f:  call   0xb7eb3364 --> {pc}: call {entrypoint}

`0x00000000b7eb335f` is the `pc`, and `0xb7eb3364` is the `entrypoint`. Furthermore, when searching in the assembly dump by this `entrypoint`, you will find:

    Prog point: 0x00000000b7eb3364 {guest_instr_count=120206427} 
`0x00000000b7eb3364` is the `entrypoint`, and `120206427` is the `instr_count`

An example of memory `reads` or `writes` array if populated is as follows:

    [{"base":"2fef50","entropy":2.0,"len":4,"nulls":0,"pc":"77a6563a","printableChars":3},{"base":"2fef64","entropy":1.5,"len":4,"nulls":2,"pc":"77a6557f","printableChars":0},{"base":"2fef70","entropy":2.1666159629821777,"len":32,"nulls":18,"pc":"77a65590","printableChars":9},{"base":"2fefa0","entropy":3.022055149078369,"len":12,"nulls":3,"pc":"77a6555c","printableChars":5},{"base":"2fefb8","entropy":2.0,"len":4,"nulls":0,"pc":"77a65597","printableChars":3},{"base":"77551000","entropy":5.467597484588623,"len":352,"nulls":3,"pc":"77a655d2","printableChars":179}]
  

Arguments
---------

* `asids`: string, mandatory. An ASCII string of asids to examine, each asid is in hex format. The argument also accepts multiple asids seperated by '_'. E.g., 0x08ca0000, or 0x08ca0000_0x08ca0000.
* `endat`: uint64, optional. The instruction count of when to end the replay.
* `call_limit`: uint32, defaults to 32. The limit of the number of calls to monitor per entrypoint (or per function call).
* `stack_limit`: uint32, defaults to 2. The limit of the callstack or functionstack to log, i.e., the length of the stack array.
* `hex`: bool, defaults to `false`. If `false`, addresses in the `func_stats` report will be formated as hex. Otherwise, it will be uint64.

Dependencies
------------

- Depends on the `callstack_instr` plugin to get information about the calling context when encountering 'on_call' or 'on_ret' callbacks, additionally it is necessary to get the calling context on the execution of basic blocks and memory reads/writes.
- JSON for Modern C++ version 3.1.2.

APIs and Callbacks
------------------

None.

Example
-------

`$PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo -panda func_stats:asids=0x0fb45000_0x08ca0000,hex=true,call_limit=200,stack_limit=16`