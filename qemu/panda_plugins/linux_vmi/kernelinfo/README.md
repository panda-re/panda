# DECAF Kernel Information Module

For DECAF to be able to examine the structure of the running kernel,
it needs to know several offsets within the data structures used by the
kernel.  E.g. what is the offset of ``pid`` within ``struct task_struct``?

These offsets are dependent on the kernel version *and* the flags used to
compile it. Some of them could be guessed using heuristics. 
A more robust approach is retrieving them by querying the running kernel.

The kernel modules in this directory implement this approach.
After compiling and inserting the modules into the kernel, the required
offsets are printed in the kernel log.
From there, they have to be copied in a ``kernelinfo.conf`` file on the
host, for DECAF to read and use.

Two files are contained here:

* ``procinfo.c``: This is a standalone module to be compiled and inserted
  using ``insmod`` command. The module initialization will (intentionally)
  always fail. But the required offset will have been printed in the 
  kernel log before that.
* ``goldfish_audio.c``: This file contains code to be pasted inside the
  ``init_module()`` function of an existing module. If the module is 
  auto-loaded (like the goldfish-audio module in Android), then the
  offset will be printed in the kernel log without requiring further
  action from the user.

In general, using the ``procinfo`` module should be preferred, as it is
less intrusive.
