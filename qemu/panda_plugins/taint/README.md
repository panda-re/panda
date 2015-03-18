PIRATE: Platform for IR-based Analyses of Tainted Execution
========

*Last updated 12/31/14*

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

Building
--------
The taint plugin and associated artifacts are compiled as part of our QEMU build
process, and plugins are built for each architecture in
`panda/qemu/<architecture>/panda_plugins/panda_taint.so`.

Using
--------
The taint plugin works with both QEMU user mode and QEMU whole system mode.  It
works using the standard `-panda` switch on QEMU's command line or
monitor, specifying the desired `panda_taint.so` to use.

To use the plugin on QEMU whole system mode, we highly recommend using it in
conjunction with our record/replay system.  This will allow a fast recording of
the execution of interest without using the plugin, and subsequent replays of
the recording with the heavyweight taint analysis enabled.

There are many ways to perform taint labeling and querying.  The primary method
we currently use is to make hypercalls from the guest into the hypervisor with
the parameters.  The implementation of the hypercall can be seen in
`panda/qemu/panda_plugins/taint/taint.cpp` at the guest hypercall callback.
More information about using the hypercall can be seen in the file tainting
tools in `panda/qemu/panda_tools/pirate_utils` which allow configurable
ways to apply taint labels to files on the system.

There are a number of command line arguments available to the taint plugin:

* `no_tainted_pointer` (default: 0)

   Tainted pointer mode is on by default, where we propagate taint if the
   pointer is tainted for memory accesses.  This disables that setting.

* `max_taintset_card` (default: off)

   Set a limit for the maximum number of labels that can be associated with an
   address in the shadow memory.  This is to help deal with taint explosion and
   the number of labels being tracked for complex computations.

* `max_taintset_compute_number` (default: off)

   Taint compute numbers track the number of computations that happen to data.
   This parameter stops propagating taint after it goes through n computations,
   becoming distant enough from the original input.

* `compute_is_delete` (default: off)

   Turns the compute taint operation into a delete operation.  This limits the
   propagation of taint only to direct copies.

* `label_incoming_network` (default: off)

   Label data coming in from the network as tainted.

* `query_outgoing_network` (default: off)

   Query taint on data going out on the network.

* `label_mode` (default: byte)

   Current taint labeling modes are binary and byte.  Binary mode tracks only
   whether or not data is tainted.  Byte mode gives each new byte its own label
   for precise tracking.  Currently, this parameter is referenced in
   `add_taint_ram()` and `add_taint_io()`.

The default invocation of of the taint plugin on a replay is:
`<architecture>/qemu-system-<arch> -replay <replay_name> -panda taint`.

To use any of these options, for example to use binary taint to look for any
labeled data leaving the system from the network, the command is:
`<architecture>/qemu-system-<arch> -replay <replay_name> -panda
taint:label_mode=binary,query_outgoing_network=1`.

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
(including Windows 7) for x86, x86_64, and ARM architectures (including
Android, since that is a supported platform in PANDA).

Adding additional support for other architectures that QEMU supports should be a
minimal porting effort that takes advantage of our alredy-existing information
flow models based on LLVM.

Hard drive and network taint is now supported for x86/64 systems.

Organization
--------
* `panda/qemu/panda_plugins/taint/taint.cpp`
    
   The main code of the plugin.  Performs initialization, defines PANDA
   callbacks, etc.

* `panda/qemu/panda_plugins/taint/llvm_taint_lib.[cpp|h]`

   Code that defines our LLVM passes, and our byte-level information flow models
   for LLVM instructions.
   
* `panda/qemu/panda_plugins/taint/taint_processor.[cpp|h]`

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

