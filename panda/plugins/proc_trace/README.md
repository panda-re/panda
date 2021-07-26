Plugin: `proc_trace`
===========

Summary
-------

The `proc_trace` plugin uses OSI to determine when the guest has scheduled a new process and dump information about that process to a pandalog.

Arguments
---------

* None

Dependencies
------------

Depends on the **osi** plugin to provide OS introspection information.

APIs and Callbacks
------------------

None. This plugin simply uses OSI's `on_task_change` callback.

Example
-------

To run `proc_trace` on an Ubuntu x64 recording:

```
~/git/panda/build/x86_64-softmmu/panda-system-x86_64 -m 1G \
  ~/.panda/bionic-server-cloudimg-amd64-noaslr-nokaslr.qcow2 \
  -pandalog out.plog -replay trace_test -panda proc_trace \
  -os linux-64-ubuntu:4.15.0-72-generic-noaslr-nokaslr
```
