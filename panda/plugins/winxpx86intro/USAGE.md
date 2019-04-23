Plugin: win7x86intro
===========

Summary
-------

`win7x86intro` is an introspection provider for Windows 7 guests, supplying information for the OSI API. Not much more to say about it; it should Just Work as long as the guest OS is Windows 7 32-bit.

Arguments
---------

None.

Dependencies
------------

`win7x86intro` is an introspection provider for the `osi` plugin.

APIs and Callbacks
------------------

None.

Example
-------

Running `osi_test` on an Windows 7 32-bit replay:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda osi -panda win7x86intro -panda osi_test

Bugs
----

The `win7x86intro` plugin currently does not support listing loaded kernel modules, even though the OSI API suggests that it should.
