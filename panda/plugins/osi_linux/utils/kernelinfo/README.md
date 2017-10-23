# Kernel Information Module

In order to be able to examine the structure of the running kernel,
several offsets within the data structures used by the kernel have to
be known.
E.g. what is the offset of ``pid`` within ``struct task_struct``?

These offsets are dependent on the kernel version *and* the flags used to
compile it. Some of them could be guessed using heuristics. 
A more robust approach is retrieving them by querying the running kernel.

The ``kernelinfo.c`` module in this directory implements this approach.
After compiling and inserting the module into the kernel, the required
offsets are printed in the kernel log.
From there, they have to be copied in a ``kernelinfo.conf`` file on the
host, for further use.
Note that the module initialization will (intentionally) always fail. But
the required offset will have been printed in the kernel log before that.

To copy the source for the module in your VM in order to compile and run
it, use the following oneliner:

```
svn export https://github.com/panda-re/panda/trunk/panda/plugins/osi_linux/utils/kernelinfo
```

To compile the module, you will need to have installed the appropriate
linux-headers package.

## Kernels from v3.3-rc1 onwards

As of [v3.3-rc1](https://github.com/torvalds/linux/releases/tag/v3.3-rc1), the structures `mnt_parent` and `mnt_mountpoint` were moved from `struct vfsmount` to `struct mount`. `struct mount` is defined in `/fs/mount.h` of the kernel source which is not included in the `linux-headers` package. Consequently, [`mount.h` from kernel 4.12](https://github.com/torvalds/linux/blob/6f7da290413ba713f0cdd9ff1a2a9bb129ef4f6c/fs/mount.h#L33) was added to this folder.

### Here be dragons! `__randomize_layout`
As of [v4.13-rc2](https://github.com/torvalds/linux/releases/tag/v4.13-rc2), `struct mount` (in `mount.h`) includes [the `__randomize_layout` annotation](https://lwn.net/Articles/723997/). We don't *think* this breaks anything, but it might be the case that the offsets are not transferrable between different builds of the same kernel.
