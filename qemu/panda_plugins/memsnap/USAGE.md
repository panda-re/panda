Plugin: memsnap
===========

Summary
-------

The `memsnap` plugin, like `memsavep`, saves a RAM snapshot; however, rather than triggering a RAM dump at a particular percentage, it instead dumps RAM when it encounters one of a given list of tap points.

The tap points are specified in a file named `tap_points.txt`, in hexadecimal, one per line.

As with `memsavep`, the snapshots are raw memory dumps suitable for analysis by Volatility or Rekall.

`memsavep` produces one memory snapshot per tap point, named according to the tap point, e.g. `8269669d.3302e1de.3eb5b3c0.mem`.

Arguments
---------



Dependencies
------------

`memsnap` relies on `callstack_instr` to get information about the current tap point.

APIs and Callbacks
------------------

None.

Example
-------

First create a `tap_points.txt`:

    8269669d 3302e1de 3eb5b3c0

Then run `memsnap`:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda callstack_instr -panda memsnap
