Plugin: pmemaccess
===========

Summary
-------

The `pmemaccess` plugin tests an experimental feature that exposes guest physical memory in QEMU over a socket. This can then be used with, e.g., Volatility to introspect on a guest VM running in PANDA.

You can find instructions for creating a Volatility profile for Linux [here](https://github.com/volatilityfoundation/volatility/wiki/Linux).

These tests depend on the VM memory having been setup. Mode 0 has a sleep call to wait for the VM to boot a little, but this is harder with mode 1 because it uses a BB callback.

It uses the request structure format defined in [memory-access.c](../../memory-access.c), and communicates through a UNIX socket.

Arguments
---------


* `path`: string, no default. The path of the UNIX socket to create.

* `mode`: 0 or 1. The test mode. 0=predefined tests, 1=Run volatility

* `profile`: string, no default. The name of the volatility profile to use.

* `command`: string, no default. The volatility command to run.


Dependencies
------------

None.

APIs and Callbacks
------------------

None.

Example
-------

Running the Volatility `pslist` command on a Windows 7 32-bit guest: 

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda pmemaccess:path=/tmp/mysock,mode=1,profile=win7sp1x86,command=pslist

Bugs
----

The plugin currently assumes that Volatility is installed at `~/git/volatility`, and this is not configurable.

The `pmemaccess` feature is not thread-safe, so the VM must be paused before running Volatility.
