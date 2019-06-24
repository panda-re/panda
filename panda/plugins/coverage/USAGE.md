Plugin: coverage
===========

Summary
-------
This plugin is used to list the address and size of every block executed, along with either the Address Space Identifier (ASID) or process ID and thread ID in effect at the time the block was executed.  The information is written to a Comma Separated Value (CSV) file to ease processing by external tools, such as IDA Pro.

The `coverage` plugin may be run in either of two modes, each of which stores additional information for each block executed.  The `process` mode (which requires Operating System Introspection (OSI) support for the guest) stores the process name, process ID and thread ID of the thread executing the block.  The `asid` mode stores the ASID in which the block was executed.  Whether or not the process was in kernel mode at the time of execution is also stored, regardless of mode.  (A value of 1 means the block was executed in kernel mode.)  The mode used to create the CSV file is also written at the top of the file, to cue parsers in as to how to interpret the file.

The default behavior is to store a record for each block only the first time it is executed for a given process and thread (for `process` mode) or ASID (for `asid` mode).  However, the `full` option can be used to store a record every time a particular block is executed.

This plugin can be used with the included `coverage.py` script in IDAPython. `coverage.py` colorizes the dissasembly in IDA Pro using the CSV file produced by this plugin.  It also provides options to add comments to the blocks noting the sequence of execution, and/or the thread ID (for `process` mode files).  The `coverage.py` script works best when there are no duplicate records, but it will also work  (more slowly) if the file was produced using the `full` option.

To use the `coverage.py` script, open your target binary in IDA Pro, import the script in the File -> Script Command window, ensure the Scripting Language is set to Python, click Run, and when prompted supply the path to the CSV file and the process or ASID you are analyzing.  You can also turn off the sequence number or  (if applicable) thread ID comments by unchecking the appropriate check box.

Note, this script assumes IDA has loaded your binary with the correct base address.  It usually works without manual adjustment for binaries executed in 32-bit Linux or Windows guests.  The base address and/or segment may need to be adjusted manually for DOS operating systems.

Arguments
---------
`filename` - The name of the file to output (default:  `coverage.csv`).
`mode` - Type of segregation used for blocks (`process` (the default if `-os` is specifed), or `asid`)
`full` - When `true`, logs each block every time it is executed (default:  `false`)
`buffer_size` - size of buffer, in bytes, for `filename` (default is `BUFSIZ`, 0=no buffer)

Dependencies
------------
osi (if `mode` is `process`)

APIs and Callbacks
------------------
None

Example
-------
```
qemu-system-i386 -m 2G -replay test \
    -os windows-32-xpsp3 \
    -panda coverage:filename=test_coverage.csv,mode=process
```
