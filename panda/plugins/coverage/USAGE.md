Plugin: coverage
===========

Summary
-------
This plugin is used to list the address and size of every block executed, along with either the Address Space Identifier (ASID) or process ID and thread ID in effect at the time the block was executed.  The information is written to a Comma Separated Value (CSV) file to ease processing by external tools, such as IDA Pro.

The `coverage` plugin may be run in either of two modes, each of which stores additional information for each block executed.  The `process` mode (which requires Operating System Introspection (OSI) support for the guest) stores the process name, process ID and thread ID of the thread executing the block.  The `asid` mode stores the ASID in which the block was executed.  Whether or not the process was in kernel mode at the time of execution is also stored, regardless of mode.  (A value of 1 means the block was executed in kernel mode.)  The mode used to create the CSV file is also written at the top of the file, to cue parsers in as to how to interpret the file.

The default behavior is to store a record for each block only the first time it is executed for a given process and thread (for `process` mode) or ASID (for `asid` mode).  However, the `full` option can be used to store a record every time a particular block is executed.  (Due to a known issue, a block which starts execution, but then exits while still in the prologue added by the translator is still recorded as a executed block.  This results in duplicate entries when the block is finally executed to completion after handling whatever interrupted it the first time around.)

When using the `coverage` plugin with a live guest system, it is also possible to enable and disable the instrumentation using monitor commands.  If desired, the plugin can be loaded as normal using PANDA command line arguments, and (optionally) the  `start_disabled=true` argument added to tell the system not to start collecting any data yet.  (The `filename` argument is ignored in this case.)  It is also possible to wait until the guest is up to load the `coverage` plugin, using the standard `load_plugin` command.  Regardless of how the plugin was loaded, the standard  `plugin_cmd` monitor command can then be used to send the `coverage_enable` command to the plugin to start the data collection, or `coverage_disable` can be used to stop data collection.  If no file name is provided with the `coverage_enable` monitor command, then the default, `coverage.csv` is used.

This plugin can be used with the included `coverage.py` script in IDAPython. `coverage.py` colorizes the dissasembly in IDA Pro using the CSV file produced by this plugin.  It also provides options to add comments to the blocks noting the sequence of execution, and/or the thread ID (for `process` mode files).  The `coverage.py` script works best when there are no duplicate records, but it will also work  (more slowly) if the file was produced using the `full` option.

To use the `coverage.py` script, open your target binary in IDA Pro, import the script in the File -> Script Command window, ensure the Scripting Language is set to Python, click Run, and when prompted supply the path to the CSV file and the process or ASID you are analyzing.  You can also turn off the sequence number or  (if applicable) thread ID comments by unchecking the appropriate check box.

Note, this script assumes IDA has loaded your binary with the correct base address.  It usually works without manual adjustment for binaries executed in 32-bit Linux or Windows guests.  The base address and/or segment may need to be adjusted manually for DOS operating systems.

Arguments
---------
* `filename` - The name of the file to output (default:  `coverage.csv`).
* `mode` - Type of segregation used for blocks (`process` (the default if `-os` is specifed), or `asid`)
* `full` - When `true`, logs each block every time it is executed (default:  `false`)
* `buffer_size` - size of buffer, in bytes, for `filename` (default is `BUFSIZ`, 0=no buffer)
* `start_disabled` - When `true`, does not start data collection when the plugin is initialized (default:  `false`)

Monitor Commands
------------
* `help` - LIsts the following monitor commands.
* `coverage_enable` - Start collecting data to the provided file name.  Uses `coverage.csv` if no file name is provided.
* `coverage_disable` - Stop collecting data, closing the currently open file.

Dependencies
------------
osi (if `mode` is `process`)

APIs and Callbacks
------------------
None

Example
-------
Use the coverage plugin with a recording:
```
qemu-system-i386 -m 2G -replay test \
    -os windows-32-xpsp3 \
    -panda coverage:filename=test_coverage.csv,mode=process
```
Use the coverage plugin on a live system:
```
quemu-system-i386 -monitor stdio -m 2G -net nic -net user -os linux-32-.+ -panda osi -panda osi_linux:kconf_file=myconf.conf,kconf_group=mygroup -hda myimage.img
(qemu) load_plugin coverage,filename=test01.csv,mode=process
PANDA[core]:initializing coverage
PANDA[coverage]:output file name test01.csv
PANDA[coverage]:file buffer_size 8192
PANDA[coverage]:log all records DISABLED
PANDA[coverage]:mode process
PANDA[core]:loading required plugin osi
PANDA[core]:/omitted/for/sake/of/security/panda_osi.so already loaded
PANDA[coverage]:start disabled DISABLED
(qemu) plugin_cmd help
PANDA[coverage]:coverage_enable=filename:  start logging coverage information to the named file
PANDA[coverage]:coverage_disable:  stop logging coverage information and close the current file
...(do something interesting in the guest)...
(qemu) plugin_cmd coverage_disable
...(do something do not want recorded)...
(qemu) plugin_cmd coverage_enable=test02.csv
...(do something interesting in the guest)...
(qemu) plugin_cmd coverage_disable
```
