Plugin: winxpx86intro
===========

Summary
-------

`winxpx86intro` is an introspection provider for Windows XP guests, supplying information for the OSI API. Not much more to say about it; it should just work as long as the guest OS is Windows XP SP3.

Arguments
---------

None.

Dependencies
------------

`winxpx86intro` is an introspection provider for the `osi` plugin.

APIs and Callbacks
------------------

None.

Example
-------

Running `osi_test` on an Windows XP 32-bit replay:

    $PANDA_PATH/i386-softmmu/panda-system-i386 -replay foo \
        -panda osi -panda win7x86intro -panda osi_test
