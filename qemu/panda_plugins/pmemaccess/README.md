QemuMemoryAccess test plugin
===
This plugin tests the QemuMemoryAccess feature.

It uses the request structure format defined in
[memory-access.c](../../memory-access.c),
and communicates through a UNIX socket.

Usage
---
You can call this plugin in the same way as any other PANDA plugin.

Arguments:
* `path="/path/to/socket"`

  The path of the UNIX socket to create

* `mode=[0,1]`

  The test mode. 0=predefined tests, 1=Run volatility

* `profile="volatility profile"`

  The name of the volatility profile to use

* `command="volatility cmd"`

  The volatility command to run

Notes:

You can find instructions for creating a Volatility profile for Linux
[here](https://github.com/volatilityfoundation/volatility/wiki/Linux).

These tests depend on the VM memory having been setup. Mode 0 has a sleep call to wait
for the VM to boot a little, but this is harder with mode 1 because it uses a BB callback.

