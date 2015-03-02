ida_taint
========

This is currently a first stab at integrating the PANDA taint analysis with IDA
Pro.  After running this analysis, a file is output that can be ingested by the
associated IDAPython script that will allow annotation (coloring) of
instructions that process tainted data, and the functions that they belong to.

Using
--------
This plugin relies on the OSI and taint plugins (with tainted instructions
enabled).  The corresponding PANDA args for a replay are
`-panda 'taint:tainted_instructions=1;osi;win7x86intro;ida_taint'`.  Currently,
only Windows 7 is supported but other operating systems could be easily added.

After running a replay with the plugin, you should see `ida_taint.json` which
shows every tainted instruction and corresponding process from the replay.
Then, `ida_taint.bat` can be used to invoke IDA with the JSON file, process
name, and original executable.

