# Kernel Information Module via gdb

First. Go read the normal kernelinfo [readme](https://github.com/panda-re/panda/blob/master/panda/plugins/osi_linux/utils/kernelinfo/README.md).

## Where does this apply

Kernels with debug symbols. Likely one that you built. If it's stripped go back to the other method.

## Requirements

- GDB 8 or above. This is needed for the GDB API to support `gdb.execute(to_string=True)`
- Python 3.6 or above. This is to support fstrings.

## How does this work?

This crux of this is python script run inside of gdb. 

That script creates a command `kernel_info`. That command takes an argument for the file to output to. Otherwise it prints to stdout.

Inside of the script you can see the gdb magic required to get offsets and whatnot for kernel information.
 
