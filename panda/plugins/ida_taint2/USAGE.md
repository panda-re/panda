Plugin: ida_taint2
===========

Summary
-------
This plugin is intended to be used with the included `ida_taint2.py` script in
IDAPython. `ida_taint2.py` colorizes  and renames functions in IDA based on the
output CSV file from this plugin. This plugin produces a CSV file of process IDs
and program counter values. There should be no duplicate rows in the file.
An entry in the CSV file indicates that the instruction at the PC manipulated
tainted data. The PID is needed because the reported addresses are virtual
addresses and so one address may be in two different processes. A process ID of
0 indicates the system is in kernel mode.

The `ida_taint2.py` script reads the CSV file and highlights functions and
instructions that manipulate tainted data. Functions are highlighted green and
individual instructions are highlighted in orange. Additionally, function names
are updated with a prefix of "TAINTED_" so that it becomes possible to search
for functions that manipulated tainted data.

To use the ida_taint2.py script, open your target binary in IDA Pro, import
the script in the File -> Script Command window, click run, and when prompted
supply the path to the CSV file and the process ID you are analyzing.

Note, this script assumes IDA has loaded your binary with the correct base
address. For 32-bit Linux and Windows guests, this script should just work
(tested with IDA 7.1). The base address and/or segment may need to be adjusted
manually for DOS operating systems.

Arguments
---------
filename - The name of the file to output (default: ida_taint2.csv).

Dependencies
------------
osi
taint2

APIs and Callbacks
------------------
None

Example
-------
```
qemu-system-i386 -m 2G -replay test \
    -panda stringsearch:str="hello world" \
    -panda tstringsearch \
    -panda ida_taint2
```
