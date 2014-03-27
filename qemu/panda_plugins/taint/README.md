PIRATE: Platform for IR-based Analyses of Tainted Execution
========

*Last updated 2/24/14*

This is our implementation of architecture-independent dynamic taint analysis.
To perform this analysis, we rely on dynamic code translation to the LLVM
intermediate representation.  From there, we use our architecture-independent
information flow models developed for LLVM to track how data flows between
instructions.

By default, QEMU translates all guest architectures (14 in total) to it's own
internal IR called TCG (Tiny Code Generator).  This IR is not robust enough for
our analyses, so we leverage the translation module from S2E to translate a step
further to LLVM.  In order to handle taint propagation through QEMU's helper
functions, we use Clang to translate the relevant helper functions to the LLVM
IR.  This allows us to have complete and correct information flow models for
code that executes within QEMU, without having to worry about
architecture-specific details.

Dealing with QEMU Helper Functions
--------
Correctly processing QEMU helper functions is essential for our analysis to be
complete and correct.  We have determined the necessary helper functions to be
included in the analysis, and we deposit these into a single module at compile
time at `panda/qemu/<architecture>/llvm-helpers.bc`.  This module is then
consumed during the taint analysis, and information is tracked properly through
helper functions.

Supported/Tested Systems
--------
While our system hasn't undergone significant testing, we currently expect it to
work for any user program or operating system that can boot in QEMU 1.0.1
(including Windows 7 + 8) for x86, x86_64, and ARM architectures (including
Android, since that is a supported platform in PANDA).

Adding additional support for other architectures that QEMU supports should be a
minimal porting effort that takes advantage of our alredy-existing information
flow models based on LLVM.

Hard drive taint is now supported for x86/64 systems.

Organization
--------
* `panda/qemu/panda_plugins/taint/taint.cpp`
    
   The main code of the plugin.  Performs initialization, defines PANDA
   callbacks, etc.

* `panda/qemu/panda_plugins/taint/llvm_taint_lib.[cpp|h]`

   Code that defines our LLVM passes, and our byte-level information flow models
   for LLVM instructions.
   
* `panda/qemu/panda/taint_processor.[c|h]`

   Code that defines our taint operations, and deals with processing those
   operations on a basic block granularity.  Other relevant code, including the
   shadow memory, is included in `panda/qemu/panda`.

* `panda/qemu/panda/panda_dynval_inst.[cpp|h]`

   LLVM function pass that deals with instrumenting LLVM code to keep a log of
   dynamic values.  This allows us to reconcile dynamic values from the
   currently executing LLVM code.
   
* `panda/qemu/panda/panda_helper_call_morph.[cpp|h]`

   LLVM function pass for code translated from TCG that changes calls to helper
   functions to calls of LLVM versions of helper functions.  This assumes that
   `llvm-helpers.bc` has been linked together with the LLVM module used by the
   LLVM JIT.

* `panda/qemu/panda_tools/helper_call_modifier/helper_call_modifier.cpp`

   Tool used at compile time during the generation of `llvm-helpers.bc` to
   perform final preparations on the module that we need for our taint analysis.
   This includes renaming helper functions to have an '_llvm' suffix, and
   several other things.

* `panda/qemu/panda_tools/bitcode_callgraph/bitcode_callgraph.cpp`

   Tool used to analyze `llvm-helpers.bc` for completeness, allowing the
   developer to verify that all relevant helper functions are included in the
   module.  Also provides additional information about the module.

Building
--------
The taint plugin and associated artifacts are compiled as part of our QEMU build
process, and plugins are built for each architecture in
`panda/qemu/<architecture>/panda_plugins/panda_taint.so`.

Using
--------
The taint plugin works with both QEMU user mode and QEMU whole system mode.  It
works using the standard `-panda-plugin` switch on QEMU's command line or
monitor, specifying the desired `panda_taint.so` to use.

To use the plugin on QEMU whole system mode, we highly recommend using it in
conjunction with our record/replay system.  This will allow a fast recording of
the execution of interest without using the plugin, and subsequent replays of
the recording with the heavyweight taint analysis enabled.

Current/Ongoing Development
--------

1. Network taint
    * PIRATE doesn't currently support taint tracking involving the
    network.  We are currently working on porting this up from our older
    QEMU-based taint analysis system.  Support for hard drive taint was recently
    completed and tested for x86/64 systems.
    
2. Optimization
    * We are currently profiling the taint plugin, characterizing performance
    overheads, and optimizing accordingly.  We also plan on optimizing our taint
    operations.

