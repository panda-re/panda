Plugin: ida_taint2
===========

Summary
-------
This plugin is intended to be used with either the `ida_taint2.py`script or `ida_taint2_plugin.py` plugin in IDAPython.  (Both of these IDAPython files are included.)  These IDAPython files use different techniiques to indicate tainted functions and instructions in IDA based on the output CSV file from this plugin. This plugin produces a CSV file of process IDs and program counter values. There are also two informational lines at the top of the file:  the first provides the PANDA build date, and the second provides the timestamp for when this CSV file was produced. There should be no duplicate rows in the file. An entry in the CSV file indicates that the instruction at the PC manipulated tainted data. The PID is needed because the reported addresses are virtual addresses and so one address may be in two different processes. A process ID of 0 indicates the system is in kernel mode.

The `ida_taint2.py` script reads the CSV file and highlights functions and instructions that manipulate tainted data. Functions are highlighted green and individual instructions are highlighted in orange. Additionally, function names are updated with a prefix of "TAINTED_" so that it becomes possible to search for functions that manipulated tainted data.  Note that both the colorization and function renaming make changes to the IDA database.  This makes the taint indications awkward to undo if you have made other changes in the database that should be kept, although the `undo_ida_taint2.py` script described below attempts to do so.  (Use the `ida_taint2_plugin.py` IDAPython plugin if it is desired to indicate tainted instructions without modifying the database.)

To use the `ida_taint2.py` script, open your target binary in IDA Pro, import the script in the File -> Script Command window, click run, and when prompted supply the path to the CSV file and the process ID you are analyzing.

To undo the changes made by the `ida_taint2.py` script, an `undo_ida_taint2.py` script is included. However, because IDA doesn't have a change tracking or undo capability, this undo script makes a best attempt at removing changes made by `ida_taint2.py`. If you've changed comments or colors after running the `ida_taint2.py` script, the undo script may undo some of your changes. This is unfortunately unpredictable. However, in each of these two scripts, an IDA database snapshot is made before actually modifying anything. In the worst case scenario you may have to restore a snapshot.

The `ida_taint2_plugin.py` IDAPython plugin indicates tainted instructions and functions without modifying the IDA database.  To use this plugin, place it in the location that your IDA installation searches for plugins.  A `PANDA:  IDA Taint2` menu item will be added to the Edit>Plugins menu.  When activated for the first time, you are prompted to select an `ida_taint2` CSV output file, and then select a process from within that file.  Tainted instructions are highlighted in orange, and a `Show Tainted Functions...` menu item is added to the `Functions window` context (right click) menu.  If you double click on a function in the `Tainted functions` window, then the disassembly view will update to show that function.  The disassembly view context menu will also have a `Hide Taint` menu item that can be used to hide the taint indications.  When taint is hidden, a `Show Taint` context menu item can be used to toggle the taint back on.  If you activate the plugin while taint information is available, then you are asked to change either the `ida_taint2` CSV file or the selected process.

Note that these scripts assume that IDA has loaded your binary with the correct base address.  For 32-bit Linux and Windows guests, these scripts should just work (tested with IDA 7.4 and 7.5).  The base address and/or segment may need to be adjusted manually for DOS operating systems.

If you are using IDA Pro (32-bit) with the Hex-Rays Decompiler, it is also possible to use the output of the `ida_taint2` plugin with the included `hexrays_ida_taint2.py` IDAPython plugin.  Place the `hexrays_ida_taint2.py` file in the folder that your installation of IDA Pro (32-bit) checks for plugins.  A `PANDA:  Pseudocode ida_taint2` menu item will be added to the Edit>Plugins menu.  If activated while the current window is a Hex-Rays Decompiler Pseudocode window, then you can select an ida_taint2 output file and process within that file to use to color the pseudocode lines that tainted instructions contributed toward.

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
panda-system-i386 -m 2G -replay test \
    -panda stringsearch:str="hello world" \
    -panda tstringsearch \
    -panda ida_taint2
```
