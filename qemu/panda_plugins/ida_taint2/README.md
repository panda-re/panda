ida_taint2
========

This is an improvement on integrating the PANDA taint analysis with IDA Pro, now
using the faster taint2 plugin and integrating with pandalogging.  After running
this analysis, a file is output that can be ingested by the associated IDAPython
script that will allow annotation (coloring) of instructions that process
tainted data, and the functions that they belong to.

Using
--------
This plugin relies on OSI, taint2, win7proc, and syscalls2 plugins.  The
corresponding PANDA args for a replay are `-panda
'syscalls2:profile=windows7_x86;ida_taint2' -pandalog <plog_file>`.  If you know
the name of the file you're working with, you can use the file_taint plugin by
adding `;file_taint:filename=<name>` to your `-panda` args.  Currently,
only Windows 7 32-bit is supported.

After running a replay with the plugin, the pandalog is populated with taint,
process introspection, and other information, and `ida_taint2.bat` can be used
to invoke IDA appropriately.  Necessary files for IDA include the binary,
scripts, pandalog, and pandalog_pb2.py which gets auto-generated during a PANDA
build.

To use with IDA, you need to install Protocol Buffers along with your Python
instance that IDA uses.  For now, we're sticking with version 2.6.1.  This can
be done with the following steps:

1. `git clone https://github.com/google/protobuf.git`
2. `git checkout tags/v2.6.1`
3. Install into your Windows python distro using the setup scripts in the
protobuf/python directory.

