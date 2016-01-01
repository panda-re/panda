Plugin: coverage
===========

Summary
-------

The `coverage` plugin gets basic information about the basic blocks executed by a particular process (as identified by a process name, using PANDA's OS introspection capability).

Arguments
---------

`coverage` takes just one argument:

* `process`: the process name for which we should print coverage information.

Dependencies
------------

Depends on the **osi** plugin to provide OS introspection information. See the documentation for the OSI plugin for more details.

APIs and Callbacks
------------------

None.

Example
-------

To run `coverage` on a Windows 7 32-bit recording and get coverage information for `explorer.exe`:

`$PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo -panda osi -panda win7x86intro -panda coverage:process=explorer.exe`

