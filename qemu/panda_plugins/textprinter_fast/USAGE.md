Plugin: textprinter_fast
===========

Summary
-------

The `textprinter_fast` plugin writes out the data read at a single tap point to a file named `read_tap_buffers.txt`. It is designed to do so with as little overhead as possible, so that it can be used on a live system (e.g., for showing demos).

The tap point to monitor is given by the input file `tap_points.txt`. Contrary to its name, it should contain just one tap point. The output is placed in `read_tap_buffers.txt`.

The plugin can also monitor writes rather than reads. However, this is currently disabled in the source so as not to slow things down. This plugin could be improved by updating it to support command line arguments.

Arguments
---------

None.

Dependencies
------------

None.

APIs and Callbacks
------------------

None.

Example
-------

First create a file called `tap_points.txt` with a single tap point:

    683158d0 686a375c 3eb5b180

Then run PANDA with `textprinter_fast`:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -hda win7.qcow2 -m 1G -monitor stdio \
        -panda textprinter_fast

If you to monitor what's written to that file, e.g. for a demo, you can then do:

    watch cat read_tap_buffers.txt
