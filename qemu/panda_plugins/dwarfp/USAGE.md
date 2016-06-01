Plugin: dwarfp
===========

Summary
-------

The `dwarp` plugin is a provider plugin for `stpi` (see [stpi](stpi/USAGE.md)).  It examines dwarf information for an executable using `libdwarf.h`, `dwarf.h` and `elf.h`.  The plugin also hooks mmap syscalls using the `loaded` plugin (see [loaded](loaded/loaded.cpp)) in order to find shared objects loaded during the lifetime of a program's execution.  At these load points, `dwarfp` will load the dwarf information for the .so file if such information exists.

Arguments
---------

* `g_debugpath`: string, defaults to "dbg". The path to the debugging file on the guest.
* `h_debugpath`: string, defaults to "dbg". The path to the debugging file on the host.
* `proc`: string, defaults to "None". The name of the process to monitor using DWARF information.

Dependencies
------------

Requires `osi` and an `osi` provider plugin.  Furthermore it requires `loaded` (hopefully this will end up in `osi`).

APIs and Callbacks
------------------

Provides only support for `stpi` callbacks.

Example
-------

Below is an example command line usage of `dwarfp`:

    ~/git/panda/qemu/i386-softmmu/qemu-system-i386 -replay \
        /nas/ulrich/dwarf_tshark_capture2/wireshark-1.2.1-saurabh.cap.iso \
        -panda osi \
        -panda osi_linux:kconf_file=/nas/ulrich/kernelinfo.conf,kconf_group=debian-3.2.51-i686 \
        -panda stpi \
        -panda dwarfp:proc=tshark,g_debugpath=/nas/ulrich/wireshark-1.2.1/lava-install/,h_debugpath=/nas/ulrich/wireshark-1.2.1/lava-install/

An example implementaiton using the `dwarfp` plugin can be found at [dwarp_simple](osi_simple/osi_simple.cpp).
