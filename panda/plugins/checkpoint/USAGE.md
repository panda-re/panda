Plugin: checkpoint
===========

Summary
-------

The `checkpoint` plugin, when enabled, takes periodic snapshots of the guest that can be used in time-travel debugging.

Arguments
---------
* `space`: string, defaults to "6G". The amount of space on RAM available to store checkpoints. Must be greater than the VM's memory size.


Dependencies
------------

APIs and Callbacks
------------------

Example
-------

To enable checkpoints and time-travel debugging, allocating 4GB of RAM to store checkpoints
```sh
$PANDA_PATH/build/x86_64-softmmu/qemu-system-x86_64 -replay foo -S -s -panda checkpoint:space=4GB
```
