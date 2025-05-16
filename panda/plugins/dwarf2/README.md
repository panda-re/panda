Plugin: dwarf2
===========

Summary
-------

The `dwarf2` plugin is to be a replacement of `pri_dwarf` plugin. The workflow is to run 
`dwarfdump -dil ${TARGET_PROG} | python -c "import sys;from pandare.extras import dwarfdump;dwarfdump.parse_dwarfdump(sys.stdin.read(), '${TARGET_PROG}')"`.
This is going to generate 4 json DWARF symbol files including: Line Info, Global Variables, Function Info, and Type Info. Place these json files under debug path for this plugin to read.

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

Provides only support for `pri` callbacks.

Example
-------

Below is an example command line usage of `dwarf2`:

    ~/git/panda/qemu/i386-softmmu/panda-system-i386 -replay \
        /nas/ulrich/dwarf_tshark_capture2/wireshark-1.2.1-saurabh.cap.iso \
        -panda osi \
        -panda osi_linux:kconf_file=/nas/ulrich/kernelinfo.conf,kconf_group=debian-3.2.51-i686 \
        -panda pri \
        -panda dwarf2:proc=tshark,g_debugpath=/nas/ulrich/wireshark-1.2.1/lava-install/,h_debugpath=/nas/ulrich/wireshark-1.2.1/lava-install/
