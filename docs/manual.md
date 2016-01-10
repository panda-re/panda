# PANDA User Manual

## Overview

PANDA (Platform for Architecture-Neutral Dynamic Analysis) is a whole-system
dynamic analysis engine based on QEMU 1.0.1. Its strengths lie in rapid reverse
engineering of software. PANDA includes a system for recording and replaying
execution, a framework for running LLVM analysis on executing code, and an
easily extensible plugin architecture. Together, these basic tools let you
rapidly understand how individual programs work and how they interact at the
system level.

## Quickstart

To build PANDA, use `panda_install.bash`, which installs all the dependencies
and builds PANDA. Don't worry; it won't actually install PANDA to a system
directory, despite the name. If you already have the dependencies you can just
run `qemu/build.sh`. Once it's built, you will find the QEMU binaries in
`i386-softmmu/qemu-system-i386`, `x86_64-softmmu/qemu-system-x86_64`, and
`arm-softmmu/qemu-system-arm`. You'll need to create a qcow (disk image) for use
with PANDA; the internet has documentation on how to do this.

We've found that the most effective workflow in PANDA is to collect a recording
of a piece of execution of interest and then analyze that recording over and
over again. You can read more about record/replay in [our
docs](record_replay.md). For now, what you need to know is that record/replay
allows you to repeat an execution trace with all data exactly the same over and
over again. You can then analyze the execution and slowly build understanding
about where things are stored, what processes are running, when the key
execution events happen, etc.

### Record

You can record execution by using the `begin_record` and `end_record` commands
in the QEMU monitor. To use the monitor, run QEMU with `-monitor stdio` (there
are [more complicated setups](https://en.wikibooks.org/wiki/QEMU/Monitor)
too). Type `begin_record "replay_name"` to start the recording process, and use
`end_record` to end it.

Recording will create two files: `replay_name-rr-snp`, the VM snapshot at
beginning of recording, and `replay_name-rr-nondet.log`, the log of all
nondeterministic inputs. You need both of those to reproduce the segment of
execution.

### Replay

You can replay a recording (those two files) using `qemu-system-$arch -replay
replay_name`. Make sure you pass the same memory size to the VM as you did for
the recording. Otherwise QEMU will fail with an incomprehensible error.

### Analysis

Once you've captured a replay, you should be able to play it over and over
again. We typically begin by using standard analyses to try and get a basic
picture of what's going on, followed by custom plugins to get more specific
analysis. Plugins reside in the [`panda_plugins`](../qemu/panda_plugins)
directory. Although the process depends on the example, some of the plugins we
often use to begin analysis are [`asidstory`](../qemu/panda_plugins/asidstory),
[`stringsearch`](../qemu/panda_plugins/stringsearch), and
[`file_taint`](../qemu/panda_plugins/file_taint).

## A Tour of Qemu

In order to use PANDA, you will need to understand at least some things about
the underlying emulator, QEMU.  In truth, the more you know about Qemu the
better, but that it is a complicated beast

### Qemu's Monitor

This is how you can access and control the emulator, to do all manner of things
including connecting an ISO to the CD drive and recording execution.  For full
details on what you do with the monitor, consult the Qemu manual.

The most common way of interacting with the monitor is just via `stdio` in the
terminal from which you originally entered the commandline that started up
Panda.  To get this to work, just add the following to the end of your
commandline: `--monitor stdio`.  There are also ways to connect to the monitor
over a telnet port etc -- refer to ethe Qemu manual for details.

Here are few monitor functions we commonly need with PANDA.

* Connect an ISO to the cd drive: `change ide1-cd0 foo.iso`.
* Begin/end recording: `begin_record foo` and `end_record`.

### Emulation details

Qemu emulates a large number of instruction set architectures, but only a few of
them are heavily used by PANDA reverse engineers.  In particular, PANDA support
is reasonably strong only for `x86`, `arm`, and `ppc`.

It is necessary to have a mental model of how Qemu emulates guest code in order
to write plugins.  Consider a basic block of guest code that Qemu wants to
emulate.  It disassembles that code into guest instructions, one by one,
simultaneously assembling a parallel basic block of instructions in an
intermediate language (IL).  This intermediate language is described in a
[README](https://github.com/moyix/panda/blob/master/qemu/tcg/README) if you are
interested.  From this IL, Qemu generates a corresponding basic block of binary
code that is directly executable on the host.  Note that it is from this Qemu IL
that PANDA generates LLVM instructions, as the two are fairly close already (our
LLVM translation is actually borrowed from the [S2E](http://s2e.epfl.ch/)
project). This basic block of code is actually executed, on the host, in order
to emulate guest behavior. Qemu toggles between translating guest code and
executing the translated binary versions. As a critical optimization, Qemu
maintains a cache of already translated basic blocks.

Here is how some of the plugins fit into that emulation sequence.

* PANDA_CB_BEFORE_BLOCK_TRANSLATE is before the initial translation of guest
  code. We don't know length of the block at this point.

* PANDA_CB_AFTER_BLOCK_TRANSLATE is after the translation of guest code. In this
  case we know how long the block is.

* PANDA_CB_BEFORE_BLOCK_EXEC is after the block of guest code has been
  translated into code that can run on the host and immediately before Qemu runs
  it.

* PANDA_CB_AFTER_BLOCK_EXEC is immediately after the block of translated guest
  code has actually been run on the host.

* PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT is right after the guest code has
  been translated into code that can run on the host, but before it runs.  In
  some situations, plugin code determines that it is necessary to re-translate
  and can trigger that here, in particular in order to support LLVM lifting and
  taint.

* PANDA_CB_INSN_TRANSLATE is just before an instruction is translated, and
  allows inspection of the instruction to control how translation inserts other
  plugin callbacks such as the `INSN_EXEC` one.

* PANDA_CB_INSN_EXEC is just before host code emulating a guest instruction
  executes, but only exists if `INSN_TRANSLATE` callback returned true.

NOTE. Although it is a little out of date, the explanation of emulation in
Fabrice Bellard's original USENIX paper on Qemu is quite a good read.  "QEMU, a
Fast and Portable Dynamic Translator", USENIX 2005 Annual Technical Conference.

### What is env?

### Virtual vs physical memory

### Panda access to Qemu data structures


## Plugin Architecture
    
### Callback list with explanation of semantics and where and when each occurs in emulation

### Order of execution

### Plugin-plugin interaction

#### Plugin callbacks

#### Plugin API


## Plugin Zoo

We have written a bunch of generic plugins for use in analyzing replays. Each
one has a USAGE.md file linked here for further explanation.

### Taint-related plugins
* [taint2](../qemu/panda_plugins/taint2/USAGE.md) - Modern taint plugin.
  Required by most other taint plugins.
* [dead\_data](../qemu/panda_plugins/dead_data/USAGE.md) - Track dead data
  (tainted, but not used in branches).
* [ida\_taint2](../qemu/panda_plugins/ida_taint2/USAGE.md) - IDA taint
  integration.
* [file\_taint](../qemu/panda_plugins/file_taint/USAGE.md) - Syscall and
  OSI-based automatic tainting of file input by filename.
* [tainted\_branch](../qemu/panda_plugins/tainted_branch/USAGE.md) - Find
  conditional branches where the choice depends on tainted data.
* [tainted\_instr](../qemu/panda_plugins/tainted_instr/USAGE.md) - Find
  instructions which process tainted data.
* [taint\_compute\_numbers](../qemu/panda_plugins/taint_compute_numbers/USAGE.md)
  \- Analyze taint compute numbers (computation tree depth) for tainted data.
* [tstringsearch](../qemu/panda_plugins/tstringsearch/USAGE.md) - Automatically
  taint all occurrences of a certain string.

#### Old generation
* [taint](../qemu/panda_plugins/taint/USAGE.md) - Old taint plugin.
* [ida\_taint](../qemu/panda_plugins/ida_taint/USAGE.md) - IDA taint
  integration for old taint plugin.

### Plugins related to [Tappan Zee (North) Bridge](http://wenke.gtisc.gatech.edu/papers/tzb.pdf)
* [stringsearch](../qemu/panda_plugins/stringsearch/USAGE.md) - Mine memory
  accesses for a particular string.
* [textfinder](../qemu/panda_plugins/textfinder/USAGE.md)
* [textprinter](../qemu/panda_plugins/textprinter/USAGE.md)
* [textprinter\_fast](../qemu/panda_plugins/textprinter_fast/USAGE.md)
* [unigrams](../qemu/panda_plugins/unigrams/USAGE.md)
* [bigrams](../qemu/panda_plugins/bigrams/USAGE.md)
* [memdump](../qemu/panda_plugins/memdump/USAGE.md)
* [keyfind](../qemu/panda_plugins/keyfind/USAGE.md)
* [memsnap](../qemu/panda_plugins/memsnap/USAGE.md)
* [memstrings](../qemu/panda_plugins/memstrings/USAGE.md)
* [correlatetaps](../qemu/panda_plugins/correlatetaps/USAGE.md)
* [tapindex](../qemu/panda_plugins/tapindex/USAGE.md)

### Callstack Tracking
* [callstack\_instr](../qemu/panda_plugins/callstack_instr/USAGE.md) -
  Instruction-based callstack tracing.
* [fullstack](../qemu/panda_plugins/fullstack/USAGE.md)
* [printstack](../qemu/panda_plugins/printstack/USAGE.md)
* [callstack\_block\_pc](../qemu/panda_plugins/callstack_block_pc/USAGE.md) -
  Old block-based callstack tracing.

### Operating System Introspection (OSI) plugins
* [osi](../qemu/panda_plugins/osi/USAGE.md) - Operating system introspection
  framework.
* [osi\_linux](../qemu/panda_plugins/osi_linux/USAGE.md) - Generic Linux OSI.
* [osi\_test](../qemu/panda_plugins/osi_test/USAGE.md)
* [osi\_winxpsp3x86](../qemu/panda_plugins/osi_winxpsp3x86/USAGE.md) - OSI for
  Windows XP SP3 x86.
* [asidstory](../qemu/panda_plugins/asidstory/USAGE.md) - ASCII art view of
  process execution inside VM.
* [linux\_vmi](../qemu/panda_plugins/linux_vmi/USAGE.md) - Alternate Linux OSI
  system from DECAF.
* [debianwheezyx86intro](../qemu/panda_plugins/debianwheezyx86intro/USAGE.md) -
  OSI for Debian 7 x86.
* [testdebintro](../qemu/panda_plugins/testdebintro/USAGE.md)
* [win7x86intro](../qemu/panda_plugins/win7x86intro/USAGE.md) - OSI for Windows
  7 x86.

### System call logging & analysis

#### Current generation
* [syscalls2](../qemu/panda_plugins/syscalls2/USAGE.md) - Modern syscalls
  tracking.
* [win7proc](../qemu/panda_plugins/win7proc/USAGE.md) - Semantic pandalog
  interpretation of syscalls for Windows 7 x86.

#### Old generation
* [syscalls](../qemu/panda_plugins/syscalls/USAGE.md) - Old syscalls tracking.
* [fdtracker](../qemu/panda_plugins/fdtracker/USAGE.md) - Old file descriptor
  tracking.

### Miscellaneous
* [bir](../qemu/panda_plugins/bir/USAGE.md) - Binary Information Retrieval.
  Used to correspond executables on disk with code executing in memory.
* [tralign](../qemu/panda_plugins/tralign/USAGE.md) - Align parts of execution
  traces.
* [bufmon](../qemu/panda_plugins/bufmon/USAGE.md) - Monitor all memory accesses
  to a particular memory region.
* [coverage](../qemu/panda_plugins/coverage/USAGE.md)
* [llvm\_trace](../qemu/panda_plugins/llvm_trace/USAGE.md) - Record trace of
  dynamic information necessary for later analysis.
* [lsmll](../qemu/panda_plugins/lsmll/USAGE.md)
* [memsavep](../qemu/panda_plugins/memsavep/USAGE.md) - Create a dump of
  physical memory at a given point in a replay. The dump can then be fed to
  Volatility.
* [memstats](../qemu/panda_plugins/memstats/USAGE.md)
* [network](../qemu/panda_plugins/network/USAGE.md)
* [pmemaccess](../qemu/panda_plugins/pmemaccess/USAGE.md)
* [rehosting](../qemu/panda_plugins/rehosting/USAGE.md)
* [replaymovie](../qemu/panda_plugins/replaymovie/USAGE.md) - Write a series of
  framebuffer screenshots to the current directory. Use movie.sh to turn them
  into a movie.
* [sample](../qemu/panda_plugins/sample/USAGE.md)
* [scissors](../qemu/panda_plugins/scissors/USAGE.md) - Cut out a smaller piece
  of a given replay.
* [useafterfree](../qemu/panda_plugins/useafterfree/USAGE.md) - Track memory
  allocations and search for uses after frees.
    
## Pandalog

Why and what for.  Probably just the stuff in pandalog.md
    
    
## LLVM
        
PANDA uses the LLVM architecture from the [S2E
project](https://github.com/dslab-epfl/s2e). This means you can translate from
QEMU's intermediate representation, TCG, to LLVM IR, which is easier to
understand and platform-independent. We call this process "lifting". Lifting has
non-trivial overhead, but it enables complex analyses like our `taint2` plugin.

### Execution

We use the LLVM JIT to directly execute the LLVM code. In fact, `taint2` relies
on this capability, as it inserts the taint operations directly into the stream
of LLVM instructions. One of the quirks of the QEMU execution mopdel is that
exotic instructions are implemented as C code which changes the `CPUState`
struct. These are called *helper functions*. We use Clang to compile each of the
helper functions directly into LLVM IR. We then link the compiled helper
functions into the LLVM module containing the lifted LLVM code. When we JIT the
lifted LLVM blocks, the helper functions can be called directly. Unfortunately,
the LLVM infrastructure is pretty slow; expect roughly a 10x slowdown with
respect to QEMU's normal TCG execution mode.

### How to use it for analysis

You can access the LLVM code for a certain `TranslationBlock` by using the
`llvm_tc_ptr` field in the `TranslationBlock` struct. This is a pointer to an
`llvm::Function` object. We recommend using an `llvm::FunctionPass` to run over
each `TranslationBlock` you would like to analyze. Have the
`PANDA_CB_AFTER_BLOCK_TRANSLATE` callback run the LLVM pass. You want the pass
to insert callbacks into the generated code that accept the dynamic values as
arguments (pointers, for example). Look at `taint2`
([taint2.cpp](../qemu/panda_plugins/taint2/taint2.cpp)) for a (very
complicated) example.

## Wish List

What is missing from PANDA?  What do we know how to do but just don't have time for?  What do we not know how to do?
