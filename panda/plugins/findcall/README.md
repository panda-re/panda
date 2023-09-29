Plugin: FindCall
===========

Summary
-------

At every function call, check if the argument is one or more specified strings. Track both module+offsets and absolute addresses for calls where this occurs. Report the module+offsets and absolute addresses where ALL strings are observed.

Arguments
---------

`output_file`: Optional, path to store results at. Default is `findcall.txt` in the current directory 

Dependencies
------------
`callwitharg` must be loaded and configured with the target strings you're looking for
`callstack_instr`

APIs and Callbacks
------------------

Example
-------
