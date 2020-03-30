Plugin: ioctl
===========

Summary
-------

Linux `ioctl` introspection built on top of plugins **syscalls2** and **linux_osi**. It achieves the following:

* Adds context `ioctl`s by tieing to PID and name of initiating process, and path for the associated file descriptor.
* Decodes the 32-bit ioctl command integer into: type (e.g. device) number, function number, argument size, and direction.
* If argument size is non-zero, reads the argument buffer out of guest memory - both on request and on return.
* Logs all of the above information to PANDALOG (serialized binary) and/or JSON for later analysis.
* For rehosting: optionally make all `ioctl` requests to a specific device always succeed (zero return).

Arguments
---------

* `out_log` (string): JSON file for `ioctl` logging (optional)
* `rehost_device_path` (string): force all `ioctl` calls to this device (e.g. `/dev/special_device` to return success (optional)

Dependencies
------------

* Uses **syscalls2** plugin hooks `on_sys_ioctl_enter` and `on_sys_ioctl_return`.
* Uses **linux_osi** plugin to determine process PID and name, and translate file descriptor to a path.

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

If `ls -l` is executed in the guest, the JSON log will contain entries for `bash` interacting with `dev/ttyS0`:

TODO: update this

```json
...
{ "proc_pid": "346", "proc_name": "bash", "file_name": "/dev/ttyS0", "type": "IO", "code": "0x0000000000000054", "func_num": "0x0000000000000010" },
{ "proc_pid": "346", "proc_name": "bash", "file_name": "/dev/ttyS0", "type": "IO", "code": "0x0000000000000054", "func_num": "0x0000000000000001" },
{ "proc_pid": "346", "proc_name": "bash", "file_name": "/dev/ttyS0", "type": "IO", "code": "0x0000000000000054", "func_num": "0x0000000000000013" },
...
```