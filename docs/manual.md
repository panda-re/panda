PANDA User Manual
=================

Overview
--------

PANDA (Platform for Architecture-Neutral Dynamic Analysis) is a whole-system dynamic analysis engine based on QEMU 1.0.1. Its strengths lie in rapid reverse engineering of software. PANDA includes a system for recording and replaying execution, a framework for running LLVM analysis on executing code, and an easily extensible plugin architecture. Together, these basic tools let you rapidly understand how individual programs work and how they interact at the system level.

Quickstart
----------

To build PANDA, use `panda_install.bash`, which installs all the dependencies and builds PANDA. Don't worry; it won't actually install PANDA to a system directory, despite the name. If you already have the dependencies you can just run `qemu/build.sh`. Once it's built, you will find the QEMU binaries in `i386-softmmu/qemu-system-i386`, `x86_64-softmmu/qemu-system-x86_64`, and `arm-softmmu/qemu-system-arm`. You'll need to create a qcow (disk image) for use with PANDA; the internet has documentation on how to do this.

We've found that the most effective workflow in PANDA is to collect a recording of a piece of execution of interest and then analyze that recording over and over again. You can read more about record/replay in [our docs](record_replay.md). For now, what you need to know is that record/replay allows you to repeat an execution trace with all data exactly the same over and over again. You can then analyze the execution and slowly build understanding about where things are stored, what processes are running, when the key execution events happen, etc.

### Record

You can record execution by using the `begin_record` and `end_record` commands in the QEMU monitor. To use the monitor, run QEMU with `-monitor stdio` (there are [more complicated setups](https://en.wikibooks.org/wiki/QEMU/Monitor) too). Type `begin_record "replay_name"` to start the recording process, and use `end_record` to end it.

Recording will create two files: `replay_name-rr-snp`, the VM snapshot at beginning of recording, and `replay_name-rr-nondet.log`, the log of all nondeterministic inputs. You need both of those to reproduce the segment of execution.

### Replay

You can replay a recording (those two files) using `qemu-system-$arch -replay replay_name`. Make sure you pass the same memory size to the VM as you did for the recording. Otherwise QEMU will fail with an incomprehensible error.

### Analysis

Once you've captured a replay, you should be able to play it over and over again. We typically begin by using standard analyses to try and get a basic picture of what's going on, followed by custom plugins to get more specific analysis. Plugins reside in the [`panda_plugins`](../qemu/panda_plugins) directory. Although the process depends on the example, some of the plugins we often use to begin analysis are [`asidstory`](../qemu/panda_plugins/asidstory), [`stringsearch`](../qemu/panda_plugins/stringsearch), and [`file_taint`](../qemu/panda_plugins/file_taint).


A Tour of Qemu Tour
-------------------

What does a PANDA user need to know about Qemu?

### Qemu's Monitor

### Emulation details

### What is env?

### Virtual vs physical memory

### Panda access to Qemu data structures


Plugin Architecture
-------------------
    
### Callback list with explanation of semantics and where and when each occurs in emulation

### Order of execution

### Plugin-plugin interaction

#### Plugin callbacks

#### Plugin API


Plugin Zoo
----------

### scissors

### asidstory

### syscalls2

### taint2

### file\_taint

### tainted\_branch

### tainted\_instructions

### Others?    

    
Pandalog
--------

Why and what for.  Probably just the stuff in pandalog.md
    
    
LLVM
----
        
### Execution

### How to use it for analysis


Wish List
---------

What is missing from PANDA?  What do we know how to do but just don't have time for?  What do we not know how to do?
