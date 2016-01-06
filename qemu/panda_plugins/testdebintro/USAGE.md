Plugin: testdebintro
===========

Summary
-------

Despite its name, `testdebintro` is not actually specific to Debian introspection. Rather, it is a test plugin that can be used to see if `osi` is working, similar to the `osi_test` plugin. Instead of printing out information periodically as `osi_test` does, it instead implements a monitor callback so that whenever `plugin_cmd pid` is entered the monitor it will dump out the current process and a list of running processes.

Arguments
---------

None.

Dependencies
------------

`testdebintro` uses the `osi` plugin to provide information about the guest operating system. As with other plugins based on `osi`, you will also need an *introspection provider* such as `win7x86intro` or `osi_linux`.

APIs and Callbacks
------------------

None.

Example
-------

The `testdebintro` plugin can be run on a live VM. Supposing we have a Windows 7 32-bit virtual machine:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -hda win7.qcow2 -m 1G -monitor stdio \
        -panda osi -panda win7x86intro -panda testdebintro

Then, while the system is running, enter at the qemu monitor:

    QEMU 1.0,1 monitor - type 'help' for more information
    (qemu) plugin_cmd pid

