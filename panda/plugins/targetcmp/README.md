Plugin: TargetCmp
===========

Summary
-------

At every function call, check the first two potential arguments to identify if it's a string pointer to a specified value. If so, examine the other pointer. If that's a string, record it's value.

The goal here is to dynamically identify values that are compared against a known string.

Arguments
---------

`output_dir`: Optional, directory to store results in. File will be created named targetcmp.txt in this directory. Current directory if unset.
`target_str`: String to search for.

Dependencies
------------
`callstack_instr`

APIs and Callbacks
------------------

Example
-------
