Plugin: dead_data
===========

Summary
-------

The `dead_data` plugin measures how often tainted data is used to decide branches in the replay. `dead_data[l]` is a count of the number of number of times the taint label `l` was seen to be involved in a tainted branch. If `l` is a positional label (i.e., if it tracks the offset within some input), then this is the number of times byte `l` in the labeled region (file?) was used to decide some branch.

This is a possible measure of the "deadness" of data. If a particular byte in the input is never used to decide any branches, then it can be assigned to any value without that causing any change in control-flow. The higher this number is, the more branches depend upon this data and thus the less likely that it can be considered dead.

Arguments
---------

None.

For writing output, `dead-data` supports [pandalog](docs/pandalog.md), and will write information about the liveness of each taint label to the pandalog if you provide a filename with the `-pandalog` argument to QEMU.

Dependencies
------------

`dead_data` uses the `taint2` plugin to track tainted branches. You will probably also want to use it in conjunction with a plugin that applies taint labels some data, such as `tstringsearch` or `file_taint`.

APIs and Callbacks
------------------

None.

Example
-------

To track liveness of taint labels in a file called `foo.txt` on Windows 7 32-bit, writing data out to a pandalog named `foo.plog`:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo -panda osi -panda win7x86intro \
        -panda syscalls2:profile=windows7_x86 -panda file_taint:filename=foo.txt,pos \
        -panda dead_data -pandalog foo.plog
