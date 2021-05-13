Plugin: syscall_logger
===========

Summary
-------

This plugin logs all system call parameters and return values to PANDALOG (serialized binary format).
By default, only primitive argument types are recorded.
For example, `sys_newuname`'s sole argument is a struct pointer:

```
{
  "pc": "1996222360",
  "instr": "0",
  "asid": "4294967295",
  "syscall": {
    "pid": 1,
    "ppid": 0,
    "tid": 1,
    "createTime": "180000000",
    "retcode": "0",
    "callName": "sys_newuname",
    "args": [
      {
        "argName": "name",
        "ptr": "2122525392"
      }
    ]
  }
},
```

If a JSON file containing DWARF information for the target kernel is provided as a plugin argument, the plugin will automatically lift the JSON contents into an internal datastructure that allows it to read any kernel structures from memory programmatically.
For any system call that takes a struct or struct pointer as an argument, the plugin will resolve all struct members, including recursive traversal of referenced or nested structs.
Returning to our `sys_newuname` example, a PANDALOG entry will look like:

```
{
  "pc": "1995861912",
  "instr": "0",
  "asid": "4294967295",
  "syscall": {
    "pid": 1,
    "ppid": 0,
    "tid": 1,
    "createTime": "190000000",
    "retcode": "0",
    "callName": "sys_newuname",
    "args": [
      {
        "argName": "name",
        "structType": "new_utsname",
        "structData": {
          "members": [
            {
              "argName": "sysname",
              "str": "Linux"
            },
            {
              "argName": "nodename",
              "str": "(none)"
            },
            {
              "argName": "release",
              "str": "4.4.138"
            },
            {
              "argName": "version",
              "str": "#1 SMP Wed Nov 4 23:03:38 EST 2020"
            },
            {
              "argName": "machine",
              "str": "armv7l"
            },
            {
              "argName": "domainname",
              "str": "(none)"
            }
          ]
        }
      }
    ]
  }
},
```

Current Limitations
---------

This method of using DWARF info for dynamically bootstrap memory layout and type info for all kernel data structures seems to work reasonably well, but it hasn't yet been tested extensively.
There are likely bugs in this plugin - please open issues/PRs if found.

At present, reading the following data types isn't supported:

* Bitfields
* Unions
* Enums
* 2D arrays

Writing kernel datastructures isn't yet implemented, but the same type/layout information used for reading can be leveraged for writing.

This plugin depends on `syscalls2`.
In some cases, `syscalls2` may fail to hook a system call (unknown ordinal) or return a `NULL` argument pointer (ABI bug).
This plugin will log an error in such cases.

Generating a DWARF JSON for a Linux Kernel
---------

1. Build a kernel with debug symbols (e.g. `CONFIG_DEBUG_INFO=y`).
2. Locate the decompressed kernel image (e.g. `vmlinux`, you can still provide the compresses version, e.g. `zImage` to PANDA).
3. Install the Go programming language toolchain, as [outlined here](https://golang.org/doc/install), if you don't have it already.
4. Clone and build [Volatility's `dwarf2json` tool](https://github.com/volatilityfoundation/dwarf2json).
5. Run `dwarf2json linux --elf your_vmlinux > vmlinux_dwarf_info.json`.
6. The resulting JSON file is an optional argument to this plugin.

See [setup_dbg.sh](./dbg/setup_dbg.sh) for an example.

Arguments
---------

* `dwarf_json`: string, path to JSON file with the kernels DWARF info. Enables richer logging if present, as described above. Optional.
* `verbose`: bool, defaults to false. Enables verbose logging if set.
* `target`: string, name of a process to log syscalls for. If unset, syscalls for all processes are logged.

Dependencies
------------

* `syscalls2`

APIs and Callbacks
------------------

None.

Python Example
-------

See [run_dbg.py](./dbg/run_dbg.py) for a usage example.
