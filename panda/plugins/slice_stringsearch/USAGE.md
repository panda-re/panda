Plugin: tstringsearch
===========

Summary
-------

The `tstringsearch` plugin applies taint labels to a particular string whenever it is seen being read from or written to memory. This is accomplished by registering a callback with the `stringsearch` plugin, so see the documentation for that plugin for more details.

This is very handy for doing things like tainting a string you've typed in.

Arguments
---------

* `instr_count`: uint64, defaults to 0. The instruction count at which to enable the taint system. This can provide a performance boost if you know when in the replay the string is first used.
* `pos`: boolean. Whether to use positional labels (i.e., a numbered label depending on the offset within the string).

Dependencies
------------

`tstringsearch` depends on the `stringsearch` plugin for matching strings and the `taint2` plugin for actually applying the taint labels. The `taint2` plugin will be loaded automatically by `tstringsearch` so you should not have to load it explicitly unless you want to provide custom options to `taint2`.

APIs and Callbacks
------------------

None.

Example
-------

To taint a string `bogart` and then create a pandalog named `bogart.plog` listing all branches depending on that string via the `tainted_branch` plugin:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda stringsearch:str=bogart -panda tstringsearch \
        -panda tainted_branch -pandalog bogart.plog
