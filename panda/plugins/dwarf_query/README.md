Plugin: dwarf_query
===========

Summary
-------

TODO

Generating a DWARF JSON for a Linux Kernel
---------

1. Acquire a decompressed kernel image, e.g. `vmlinux` (may need to extract from `zImage`).
2. Install the Go programming language toolchain, as [outlined here](https://golang.org/doc/install).
3. Clone and build [Volatility's `dwarf2json` tool](https://github.com/volatilityfoundation/dwarf2json).
4. Run `dwarf2json linux --elf your_vmlinux > vmlinux_dwarf_info.json`.

Arguments
---------

TODO

Dependencies
------------

TODO

APIs and Callbacks
------------------

TODO

Python Example
-------

TODO