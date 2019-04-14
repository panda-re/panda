# Plugin: osi\_pse

## Summary
The `osi_pse` plugin builds upon the `osi` plugin to implement
process-level event callbacks.
The plugin is implemented in an OS-specific way. The goal of the plugin
is to abstract-away the complexities of process creation and destruction.

### Background
Originally, it was envisioned to implement `osi_pse` in an OS-agnostic
manner, using only the functionality provided by the `osi` plugin api.
Specifically, the process lists acquired at consecutive `asid` changes
would be compared to identify new and finished processes.

However, initial experimentation with linux showed that this was not
realistic, as a fair amount of OS-specific code was still required.
The reason for this is that at creation/destruction of processes, the OS
internals go into a *transient state*. The boundaries of the transient
state do not coincide with changes to the `asid`.

In practice, this translates into running the callbacks offered by
`osi_pse` either prematurely, or very late. This would force the
plugins that use `osi_pse` to also maintain some state. E.g. if the
`on_process_start` callbacks runs while the OS is still in transient
state, the plugin that uses `osi_pse` has to "remember" to update the
details of the created process later. This is the kind of complexity
that should remain hidden under the hood of `osi_pse`.

Before `osi_pse`, similar functionality was built-on the `osi` plugin.
However, that implementation was based on the comparisson of process
listings during `asid` changes, so it suffered from the undesirable
effects we described. Moreover, the functionality was enabled with a
compile-time flag (`-DOSI_PROC_EVENTS`). The above led to the decision
to create a separate plugin.

## Arguments
Currently, the plugin does not accept any command line arguments.

## Dependencies
The plugin builds on +++

### Linux Implementation
In linux, launching a new process typically involves:
  - `sys_clone` to setup a new process.
  - `sys_execve` follows shortly after, to load the new process image.
    The system call will start but will not return if successful.
  - A context switch happens where the task is still in a transient state.
  - In the first system call after the context switch (typically a `sys_brk`)
    the task has been updated and can be introspected via the `osi` api.

@note XXX: Signature should have `target_ptr_t` as the type of all arguments.
However, syscall\_parser.py doesn't emit `target_ptr_t` for strings/pointers.

Semantics: events happen while the kernel is still in transient state.
accurate process information can be obtained at the first syscall after start.
at the time of end introspection may not be possible

start-sys\_execve
  change of asid (proc up)
  sys\_brk -> new process shows
  emit proc/end proc/start before syscall

## APIs and Callbacks
The plugin provides the following three callbacks:

---

Name: **on\_process\_start**

Signature:

```C
typedef void (*on_process_start_t)(CPUState *, OsiProcHandle *)
```

Description: Called whenever a new process is created in the guest.
Passes in an `OsiProcHandle` identifying the newly created process.

---

Name: **on\_process\_end**

Signature:

```C
typedef void (*on_process_end_t)(CPUState *, OsiProcHandle *)
```

Description: Called whenever a process exits in the guest. Passes in an
`OsiProcHandle` identifying the process that just exited.

---

## Example
TBA

