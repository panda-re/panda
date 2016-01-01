Plugin: linux_vmi
===========

Summary
-------

The `linux_vmi` plugin borrows code from DECAF/Droidscope for introspecting into Linux guests.

It is effectively replaced by the `osi_linux` plugin and considered deprecated; however, because it supports ARM guests (such as Android) it may still be useful in some scenarios.

Arguments
---------

None.

Dependencies
------------

None.

APIs and Callbacks
------------------

The `linux_vmi` plugin exposes the following APIs:

    // Caller doesn't own the result
    ProcessInfo* findProcessByPID(gpid_t pid);
    // Caller doesn't own the result
    ProcessInfo* findProcessByPGD(target_asid_t pgd);

For more details, such as the definition of the `ProcessInfo` struct, consult `linux_vmi_types.h`.

Example
-------

FIXME
