PANDA
====
PANDA is the Platform for Architecture-Neutral Dynamic Analysis.  It is a
platform based on QEMU 1.0.1 and LLVM 3.3 for performing dynamic software
analysis, abstracting architecture-level details away with a clean plugin
interface.  It is currently being developed in collaboration with MIT Lincoln
Laboratory, Georgia Tech, and Northeastern University.

Building
----
Instructions for building PANDA can be found in docs/compile.txt.

PANDA Plugins
----
Details about the architecture-neutral plugin interface can be found in
docs/PANDA.md.  Existing plugins and tools can be found in qemu/panda\_plugins
and qemu/panda\_tools.

Record/Replay
----
PANDA currently supports whole-system record/replay execution of x86, x86\_64,
and ARM guests.  Documentation can be found in docs/record\_replay.md

Android Support
----
PANDA supports ARMv7 Android guests, running on the Goldfish emulated platform.
Documentation can be found in docs/Android.md

Publications
----
* [1] B. Dolan-Gavitt, T. Leek, J. Hodosh, W. Lee.  Tappan Zee (North) Bridge:
Mining Memory Accesses for Introspection. 20th ACM Conference on Computer and
Communications Security (CCS), Berlin, Germany, November 2013.

* [2] R. Whelan, T. Leek, D. Kaeli.  Architecture-Independent Dynamic
Information Flow Tracking. 22nd International Conference on Compiler
Construction (CC), Rome, Italy, March 2013.

License
----
GPLv2.

Acknowledgements
----
This work was sponsored by the Assistant Secretary of Defense for Research and
Engineering under Air Force Contract #FA8721-05-C-0002.

