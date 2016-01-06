Plugin: osi_winxpsp3x86
===========

Summary
-------

`osi_winxpsp3x86` is an introspection provider for Windows XP SP3 32-bit guests, supplying information for the OSI API. Not much more to say about it; it should Just Work as long as the guest OS is Windows XP SP3.

Arguments
---------

None.

Dependencies
------------

`osi_winxpsp3x86` is an introspection provider for the `osi` plugin.

APIs and Callbacks
------------------

None.

Example
-------

Running `osi_test` on an Windows XP SP3 32-bit replay:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda osi -panda osi_winxpsp3x86 -panda osi_test

Bugs
----

The `osi_winxpsp3x86` plugin currently does not support listing loaded kernel modules, even though the OSI API suggests that it should.
