Plugin: sample
===========

Summary
-------

The `sample` plugin provides examples of how to do some things using PANDA's API. It currently provides examples of:

* Logging the address of instructions executed in user mode using the translate/exec callbacks.
* Printing out the address of a basic block before and after it gets executed.
* Implementing a monitor command using a monitor callback.
* Handling an in-guest *hypercall*.
* Exposing an API to other plugins.
* Hooking the `loadvm` operation (QEMU's mechanism for reverting to a snapshot) on Android.
* Parsing arguments passed to the plugin (FIXME: this should be updated to use the more convenient `panda_parse` functions).

Arguments
---------

* `file`: string, no default. The filename to write the log of instructions executed to.

Dependencies
------------

None.

APIs and Callbacks
------------------

Provides two example APIs:

    // prints "sample was passed a cpustate"
    int sample_function(CPUState *env);

    // prints "sample was passed a cpustate and parameter <foo>"
    int other_sample_function(CPUState *env, int foo);


Example
-------

The `sample` plugin isn't really meant to be run, but if you'd like to do so:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda sample:file=instr_log.txt
