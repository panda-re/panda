# PANDA

PANDA is an open-source Platform for Architecture-Neutral Dynamic Analysis. It
is built upon the QEMU whole system emulator, and so analyses have access to all
code executing in the guest and all data. PANDA adds the ability to record and
replay executions, enabling iterative, deep, whole system analyses. Further, the
replay log files are compact and shareable, allowing for repeatable experiments.
A nine billion instruction boot of FreeBSD, e.g., is represented by only a few
hundred MB. PANDA leverages QEMU's support of thirteen different CPU
architectures to make analyses of those diverse instruction sets possible within
the LLVM IR. In this way, PANDA can have a single dynamic taint analysis, for
example, that precisely supports many CPUs. PANDA analyses are written in a
simple plugin architecture which includes a mechanism to share functionality
between plugins, increasing analysis code re-use and simplifying complex
analysis development.

It is currently being developed in collaboration with MIT Lincoln
Laboratory, NYU, and Northeastern University.

## Building

Because PANDA has a few dependencies, we've encoded the build instructions into
a script, `panda_install.bash`. The script should actually work on Debian 7/8
and Ubuntu 14.04, and it shouldn't be hard to translate the `apt-get` commands
into whatever package manager your distribution uses. We currently only vouch
for buildability  on Debian 7/8 and Ubuntu 14.04, but we welcome pull requests
to fix issues with other distros.

Note that if you want to use our LLVM features (mainly the dynamic taint
system), you will need to install LLVM 3.3 from OS packages or compiled from
source. On Ubuntu 14.04 this will happen automatically via `panda_install.bash`.

We don't currently support building on Mac/BSD, although it shouldn't be
impossible with a few patches. We do rely on a few Linux-specific APIs.

## Support

If you need help with PANDA, or want to discuss the project, you can join our
IRC channel at #panda-re on Freenode, or join the [PANDA mailing
list](http://mailman.mit.edu/mailman/listinfo/panda-users).

We have a basic manual [here](docs/manual.md).

## PANDA Plugins

Details about the architecture-neutral plugin interface can be found in
[docs/PANDA.md](docs/PANDA.md). Existing plugins and tools can be found in
[qemu/panda\_plugins](qemu/panda_plugins) and
[qemu/panda\_tools](qemu/panda_tools).

## Record/Replay

PANDA currently supports whole-system record/replay execution of x86, x86\_64,
and ARM guests. Documentation can be found in
[docs/record\_replay.md](docs/record_replay.md).

## Android Support

PANDA supports ARMv7 Android guests, running on the Goldfish emulated platform.
Documentation can be found in [docs/Android.md](docs/Android.md).

## Publications

* [1] B. Dolan-Gavitt, T. Leek, J. Hodosh, W. Lee.  Tappan Zee (North) Bridge:
Mining Memory Accesses for Introspection. 20th ACM Conference on Computer and
Communications Security (CCS), Berlin, Germany, November 2013.

* [2] R. Whelan, T. Leek, D. Kaeli.  Architecture-Independent Dynamic
Information Flow Tracking. 22nd International Conference on Compiler
Construction (CC), Rome, Italy, March 2013.

* [3] B. Dolan-Gavitt, J. Hodosh, P. Hulin, T. Leek, R. Whelan.  
Repeatable Reverse Engineering with PANDA. 5th Program Protection and Reverse
Engineering Workshop, Los Angeles, California, December 2015.

* [4] M. Stamatogiannakis, P. Groth, H. Bos. Decoupling Provenance
Capture and Analysis from Execution. 7th USENIX Workshop on the Theory
and Practice of Provenance, Edinburgh, Scotland, July 2015.

## License

GPLv2.

## Acknowledgements

This work was sponsored by the Assistant Secretary of Defense for Research and
Engineering under Air Force Contract #FA8721-05-C-0002.
