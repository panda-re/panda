PANDA
====
PANDA is an open-source Platform for Architecture-Neutral Dynamic Analysis. It is built upon the QEMU whole system emulator, and so analyses have access to all code executing in the guest and all data. PANDA adds the ability to record and replay executions, enabling iterative, deep, whole system analyses. Further, the replay log files are compact and shareable, allowing for repeatable experiments. A nine billion instruction boot of FreeBSD, e.g., is represented by only a few hundred MB. PANDA leverages QEMU's support of thirteen different CPU architectures to make analyses of those diverse instruction sets possible within the LLVM IR. In this way, PANDA can have a single dynamic taint analysis, for example, that precisely supports many CPUs. PANDA analyses are written in a simple plugin architecture which includes a mechanism to share functionality between plugins, increasing analysis code re-use and simplifying complex analysis development. 

It is currently being developed in collaboration with MIT Lincoln
Laboratory, Georgia Tech, and Northeastern University.

Building
----
Instructions for building PANDA can be found in docs/compile.txt.

Support
----
If you need help with PANDA, or want to discuss the project, you can join our IRC channel at #panda-re on Freenode, or join the [PANDA mailing list](http://mailman.mit.edu/mailman/listinfo/panda-users).

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

