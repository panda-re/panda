Plugin: taint_compute_numbers
===========

Summary
-------

The `taint_compute_numbers` plugin tracks the amount of computation done on tainted data. Roughly speaking, if we have an operation like

    c = a + b

Then the *taint compute number* is computed as:

    TCN(c) = max(TCN(a),TCN(b)) + 1

Simple copies of data do not increase the taint compute number.

`taint_compute_numbers` tracks taint operations using the `taint` plugin and prints to stdout the maximum observed taint compute number whenever the taint state changes or tainted computation is observed.

**Warning**: `taint_compute_numbers` currently uses the deprecated `taint` plugin rather than the newer `taint2` plugin. 

Arguments
---------

None.

Dependencies
------------

Depends on the `taint` plugin to track taint.

APIs and Callbacks
------------------

None.

Example
-------

Using `taint_compute_numbers` is simple:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda taint -panda taint_compute_numbers
