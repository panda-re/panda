Plugin: syscalls2_errors
===========

Summary
-------

*Only supports Linux targets*.

Catches every `on_syscall2_return2_t` from the syscalls2 plugin, checks its return value, and prints the associated error with strerror. Exposes a PPP callback to catch error events.

Arguments
---------

None

Dependencies
------------
`syscalls2`



APIs and Callbacks
------------------

```
typedef void *(on_get_error_t)(CPUState *cpu, target_ulong pc, const syscall_info_t *call, const syscall_ctx_t *ctx, target_ulong sys_errorno, const char* sys_error_description);
```
Basically the same arguments as `on_all_sys_return2` from `syscalls2`, but provides *positive* error value as well as a string description of the value.

Example
-------
Use syscalls2_errors with a recording:

```
panda-system-i386 -m 1G -replay test \
    -os linux-32-ubuntu:4.0.1 \
    -panda syscalls2 -panda syscalls2_errors
```
