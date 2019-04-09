# syscalls2 mainenance

**Note:** This document is work in progress.

In this document we highlight how support for new operating systems can
be added to `syscalls2`. Overall, this is a two step process:

  A. Extract the system call prototypes for the new OS. The prototypes
     in general consist of the system call *number* and function
	 *signature*.
  B. Generate headers and source file from the prototypes, so that
     `syscalls2` will be able to intercept the system calls for the
	 target OS.

## Extracting system call prototypes

### Linux
For extracting the linux system call prototypes, you will need a
copy of the linux source. This is achieved by pointing the script
[make\_linux\_prototypes.py][mklinux-proto] to the source tree.

It is recommended to use the Ubuntu sources, as it includes a number of
additional system calls. This has the side-effect that when `syscalls2`
analyzes kernels provided by other vendors, the results for non-standatd
system calls may be off.

Ubuntu sources have the particularity that some of the headers required
by the extraction script have to be generated. Following are the rough
steps to prepare an Ubuntu source tree.

```sh
git clone git://kernel.ubuntu.com/ubuntu/ubuntu-xenial.git
cd ubuntu-xenial
git checkout Ubuntu-4.4.0-130.156
cat ./debian.master/config/{config.common.ubuntu,i386/config.common.i386,i386/config.flavour.generic} > .config
make
```

Compilation may fail after this but it doesn't matter, as long as the 
required `unistd` header files were generated.


## Generating `syscalls2` support files


mklinux-proto: prototypes/make_linux_prototypes.py

Goldfish kernel doesn't support OABI layer. Yay!
