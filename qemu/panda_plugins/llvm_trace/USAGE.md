Plugin: llvm_trace
===========

Summary
-------

The `llvm_trace` plugin creates an instruction trace from a replay. This trace includes not only the instructions executed, lifted to LLVM, but also the dynamic values necessary for following dataflow throughout the trace, including all memory loads and stores, and the result of all branch operations taken in LLVM code.

These traces can then be processed by other tools; for example, the `dynslice` tool performs dynamic slicing on

`llvm_trace` produces several files that together make up a trace. In its legacy log format, it produces:

* $BASEDIR/llvm-memlog.log : the memory operations and dynamic values needed to reconstruct dataflow
* $BASEDIR/llvm-functions.log : a list of LLVM basic blocks executed
* $BASEDIR/llvm-mod.bc : the LLVM bitcode for all basic blocks executed

If the newer TUBTF (Tim's Uncomplicated Binary Trace Format) format is used (by specifying the `tubtf` option), then the files written will be:

* $BASEDIR/tubtf.log : the trace and dynamic value log, in TUBTF format
* $BASEDIR/llvm-mod.bc : the LLVM bitcode for all basic blocks executed

Here, `$BASEDIR` refers to the base directory specified with the `base` option.

For more information on TUBTF, see `tubtf.h` in the `qemu/panda` subdirectory.

Arguments
---------

* `base`: string, defaults to "/tmp". The directory where trace logs should be stored.
* `tubtf`: boolean, whether to use use TUBTF format for logging

Dependencies
------------

None.

APIs and Callbacks
------------------

None.

Example
-------

To create a trace in the current directory in TUBTF format:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda llvm_trace:base=.,tubtf
