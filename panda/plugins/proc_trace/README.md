Plugin: `proc_trace`
===========

Summary
-------

The `proc_trace` plugin uses OSI to determine whenever the guest has switched to a new process and record this information in a pandalog file. This is a simple example to demonstrate how to use the `on_task_change` callback provided by `osi`.

The information stored by this plugin in a pandalog can be visualized by the procTrace python plugin in the pandare.extras package.

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
```
user@host:~$ $(python3 -m pandare.qcows x86_64) -panda proc_trace -plog my_proc_data.plog
```
