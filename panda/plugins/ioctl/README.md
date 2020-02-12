Plugin: ioctl
===========

Summary
-------

Linux `ioctl` introspection built on top of syscalls2.

**Filtered Hooking API (active):** APIs to hook IOCTLs by (in order of granularity least-to-most, can be applied to all processes or a specific process):
    * Access (e.g. `IOW`/`copy_to_user`)
    * Driver code (e.g. ASCII character supposedly unique to each driver)
    * Command (e.g. the 2nd syscall param)

**Logging Functionality (passive):** Collect as JSON:
    * Sequence of all `ioctl` commands by process

TODO: PyPanda client for hook APIs.

TODO: source-based command decoding.

Arguments
---------

* out_log (string): JSON file for `ioctl` logging (optional)

Dependencies
------------

* Uses **syscalls2** plugin hooks `on_sys_ioctl_enter` and `on_sys_ioctl_return`.
* Uses **linux_osi** plugin to determine process PID and name.

APIs and Callbacks
------------------

TODO

Example
-------

Testing with temporary script, log to `ioctl.json`:

```
./run_ioctl_demo.sh
```