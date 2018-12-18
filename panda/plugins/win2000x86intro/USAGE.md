Plugin: win2000x86intro
===========

Summary
-------

`win2000x86intro` is an introspection provider for Windows 2000 guests, supplying information for the OSI API. Not much more to say about it; it should Just Work as long as the guest OS is Windows 2000.

Arguments
---------

None.

Dependencies
------------

`win2000x86intro` is an introspection provider for the `osi` plugin.

APIs and Callbacks
------------------

None.

Example
-------

Running `osi_test` on an Windows 2000 32-bit replay:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda osi -panda win2000x86intro -panda osi_test
