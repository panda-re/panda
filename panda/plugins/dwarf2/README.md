Plugin: dwarf2
===========

Summary
-------

The `dwarf2` plugin is to be a replacement of `pri_dwarf` plugin.

Before running the plugin, you need to extract DWARF debug information from the target binary into json files using the `pandare.extras.dwarfdump` module. You can do this by running the following commands:

This plug-in/script is used for [LAVA](https://github.com/panda-re/lava), so it assumes that the binary has the following CFLAGS `-O0 -g -gdwarf-2 -fno-stack-protector`. 
This is because these flags ensure all the input needed for Python to parse the dwarf dump is available to plant vulnerabilities.

```bash
# Assume TARGET_PROG is the path to the target program with DWARF debug info
dwarfdump -dil ${TARGET_PROG} > tmp.dump
python3 -m pandare.extras.dwarfdump tmp.dump temp

# Alternatively, you can use the following one-liner to achieve the same result:
dwarfdump -dil <binary> | python3 -m pandare.extras.dwarfdump <binary-prefix>
```
This is going to generate 4 JSON DWARF symbol files including: 
* Line Info
* Global Variables
* Function Info
* Type Info

Place these JSON files under debug path for this plugin to read.

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
