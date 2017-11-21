Plugin: memsavep
===========

Summary
-------

The `memsavep` plugin does one thing and does it well: saves a snapshot of memory when a particular point in the replay has been reached (e.g., at 50% of the way through the replay, or after executing 3314667015 instructions). The snapshot is a raw memory snapshot suitable for analysis with Volatility or Rekall.

Once the given point in the replay has been reached and the memory has been dumped, `memsavep` terminates the replay.

Arguments
---------

`memsavep` accepts two arguments: a given point in the program, expressed with either `percent` or `instrcount`, and a filename

* `percent`: double, defaults to 200 (do not dump at percent). The percentage of the replay at which we should dump memory.
* `instrcount`: uint64, defaults to 0 (do not dump at instrcount). The instruction count of the replay at which we should dump memory.
* `file`: string, defaults to "memsavep.raw". The filename to dump RAM out to.

Dependencies
------------

None.

APIs and Callbacks
------------------

None.

Example
-------

To dump memory at 66.2% to `mymem.dd`:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda memsavep:percent=66.2,file=mymem.dd

To dump memory when an instruction count of 3314667015 is reached: 

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda memsavep:instrcount=3314667015,file=mymem.dd
