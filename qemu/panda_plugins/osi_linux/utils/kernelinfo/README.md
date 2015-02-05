# Kernel Information Module

In order to be able to examine the structure of the running kernel,
several offsets within the data structures used by the kernel have to
be known.
E.g. what is the offset of ``pid`` within ``struct task_struct``?

These offsets are dependent on the kernel version *and* the flags used to
compile it. Some of them could be guessed using heuristics. 
A more robust approach is retrieving them by querying the running kernel.

The ``procinfo.c`` module in this directory implements this approach.
After compiling and inserting the module into the kernel, the required
offsets are printed in the kernel log.
From there, they have to be copied in a ``kernelinfo.conf`` file on the
host, for further use.
Note that the module initialization will (intentionally) always fail. But
the required offset will have been printed in the kernel log before that.

