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

Running on [this QCOW](http://panda-re.mit.edu/qcows/linux/ubuntu/1804/x86_64/bionic-server-cloudimg-amd64.qcow2) with [this kernelinfo.conf](http://panda-re.mit.edu/qcows/linux/ubuntu/1804/x86_64/kernelinfo.conf), log to `ioctl.json`:

```
$PANDA_PATH/panda-system-x86_64 \
    -m 1G \
    -loadvm root \
    -nographic \
    -os linux-64-ubuntu:4.15.0-72-generic \
    -panda osi \
    -panda osi_linux:kconf_file=./kernelinfo.conf,kconf_group=ubuntu:4.15.0-72-generic:64 \
    -panda syscalls2:profile=linux_x86_64 \
    -panda ioctl:out_log="ioctl.json" \
   ./bionic-server-cloudimg-amd64.qcow
```

If `ls -l` is executed in the guest, the log will contain entries for `bash` interacting with `dev/ttyS0`:

```json
...
{ "proc_pid": "346", "proc_name": "bash", "file_name": "/dev/ttyS0", "type": "IO", "code": "0x0000000000000054", "func_num": "0x0000000000000010" },
{ "proc_pid": "346", "proc_name": "bash", "file_name": "/dev/ttyS0", "type": "IO", "code": "0x0000000000000054", "func_num": "0x0000000000000001" },
{ "proc_pid": "346", "proc_name": "bash", "file_name": "/dev/ttyS0", "type": "IO", "code": "0x0000000000000054", "func_num": "0x0000000000000013" },
...
```