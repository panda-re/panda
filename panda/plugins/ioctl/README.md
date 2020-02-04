Plugin: ioctl
===========

Summary
-------

Linux `ioctl` introspection built on top of syscalls2.

**Filtered Hooking API (active):** APIs to hook IOCTLs by (in order of granularity least-to-most, can be applied to all processes or a specific process):
    * Access (e.g. `_IOW`/`copy_to_user`)
    * Driver code (e.g. ASCII character supposedly unique to each driver)
    * Command (e.g. the 2nd syscall param)

**Logging Functionality (passive):** Collect either of the following as JSON:
    * Unique `ioctl` commands by process
    * Sequence of all `ioctl` commands by process

TODO: PyPanda client for hook APIs.

TODO: source-based command decoding.

Arguments
---------

* out_log (string): JSON file for `ioctl` logging (optional)

Dependencies
------------

None

APIs and Callbacks
------------------

TODO

Example
-------

Testing with the Debian ARM image used by PANDA's `run_debian.py --arch arm`, log to `ioctl.json`:

```
arm-softmmu/panda-system-arm -M versatilepb -kernel ~/.panda/vmlinuz-3.2.0-4-versatile \
    -initrd ~/.panda/initrd.img-3.2.0-4-versatile -hda ~/.panda/arm_wheezy.qcow \
    -monitor stdio -loadvm root \
    -panda ioctl:out_log="ioctl.json"
```