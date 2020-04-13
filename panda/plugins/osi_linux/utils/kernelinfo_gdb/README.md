# Kernel Information Module via gdb

First. Go read the normal kernelinfo [readme](https://github.com/panda-re/panda/blob/master/panda/plugins/osi_linux/utils/kernelinfo/README.md).

## Requirements

- GDB 8 or above. This is needed for the GDB API to support `gdb.execute(to_string=True)`
- Python 3.6 or above. This is to support fstrings.
- A kernel vmlinux that is not stripped

## Where does this apply?

Kernels with debug symbols. Likely one that you built. If it's stripped go back to the other method.

Example: `vmlinux: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), statically linked, BuildID[sha1]=181ca40a44bef701cf0559b185180053a152029d, with debug_info, not stripped`


## How does this work?

This crux of this is python script run inside of gdb. 

That script creates a command `kernel_info`. That command takes an argument for the file to output to. Otherwise it prints to stdout.

Inside of the script you can see the gdb magic required to get offsets and whatnot for kernel information.
 
