Plugin: osi
===========

Summary
-------

The `osi` module forms the core of PANDA's OS-specific introspection support. The `osi` plugin itself acts as a glue layer, offering a uniform API that can be called by plugins without that plugin needing to know anything about the underlying operating system. An OSI provider plugin then implements the necessary functionality for each operating system.

Expressed graphically, this arrangement looks like:

    +-------------------+  +-------------------+
    |    Your Plugin    |  |    Your Plugin    |
    +-------------------+  +-------------------+
    |        osi        |  |        osi        |
    +-------------------+  +-------------------+
    |     osi_linux     |  |    win7x86intro   |
    +-------------------+  +-------------------+

The key is that you can swap out the bottom layer to support a new operating system without needing to modify your plugin.

Arguments
---------

* `os`: the target os. Options can be seen in [common.c](/panda/src/common.c) or in the error message if you get the argument wrong, but in the correct format, e.g.: `-os windows-32-0`

Dependencies
------------

Depends on some OS-specific plugin to register callbacks that implement the various APIs OSI exposes. Otherwise, any call to OSI will simply fail to return any useful data, as the OSI plugin itself does not know anything about specific operating systems.

APIs and Callbacks
------------------

To implement OS-specific introspection support, an OSI provider should register the following callbacks:

Name: **on_get_processes**

Signature:

```C
typedef void (*on_get_processes_t)(CPUState *, OsiProcs **)
```

Description: Called to get the process list from the guest OS. The implementation should allocate memory and fill in the pointer to an `OsiProcs` struct. The returned list can be freed with `on_free_osiprocs`.

Name: **on_get_current_process**

Signature:

```C
typedef void (*on_get_current_process_t)(CPUState *, OsiProc **)
```

Description: Called to get the currently running process in the guest OS. The implementation should allocate memory and fill in the pointer to an `OsiProc` struct. The returned `OsiProc` can be freed with `on_free_osiproc`.

Name: **on_get_modules**

Signature:

```C
typedef void (*on_get_modules_t)(CPUState *, OsiModules **)
```

Description: Called to get the list of kernel modules loaded in the guest. The implementation should allocate memory and fill in the pointer to an `OsiModules` struct. The returned list can be freed with `on_free_osimodules`.

Name: **on_get_libraries**

Signature:

```C
typedef void (*on_get_libraries_t)(CPUState *, OsiProc *, OsiModules**)
```

Description: Called to get the list of shared libraries loaded for some particular process in the guest. The process should be an `OsiProc` previously returned by `on_get_current_process` or `on_get_processes`. The implementation should allocate memory and fill in the pointer to an `OsiModules` struct. The returned list can be freed with `on_free_osimodules`.

Name: **on_free_osiproc**

Signature:

```C
typedef void (*on_free_osiproc_t)(OsiProc *p)`
```

Description: Frees an `OsiProc` struct. You only need to implement this if you use a custom memory allocator (instead of the default malloc/free) in your plugin.

Name: **on_free_osiprocs**

Signature:

```C
typedef void (*on_free_osiprocs_t)(OsiProcs *ps)
```

Description: Frees an `OsiProcs` struct. You only need to implement this if you use a custom memory allocator (instead of the default malloc/free) in your plugin.

Name: **on_free_osimodules**

Signature:

```C
typedef void (*on_free_osimodules_t)(OsiModules *ms)
```

Description: Frees an `OsiModules` structure. You only need to implement this if you use a custom memory allocator (instead of the default malloc/free) in your plugin.

---------------

In addition, there are two callbacks intended to be used by `osi` *users*, rather than by introspection providers:

Name: **on_process_start**

Signature:

```C
typedef void (*on_process_start_t)(CPUState *, OsiProc *)
```

Description: Called whenever a new process is created in the guest. Passes in an `OsiProc` identifying the newly created process.
This callback is **disabled by default** because it requires a fair amount of computation.
To enable/use this callback you need to have used the `-DOSI_PROC_EVENTS` flag at compile time.


Name: **on_process_end**

Signature:

```C
typedef void (*on_process_end_t)(CPUState *, OsiProc *)
```

Description: Called whenever a process exits in the guest. Passes in an `OsiProc` identifying the process that just exited.
This callback is **disabled by default** because it requires a fair amount of computation.
To enable/use this callback you need to have used the `-DOSI_PROC_EVENTS` flag at compile time.

Data structures used by OSI:

```C
    // Represents a page of memory (TODO in osi_linux)
    typedef struct osi_page_struct {
        target_ulong start;
        target_ulong len;
    } OsiPage;

    // Represents a single process
    typedef struct osi_proc_struct {
        target_ulong offset;
        char *name;
        target_ulong asid;
        OsiPage *pages;     // TODO in osi_linux
        target_ulong pid;
        target_ulong ppid;
    } OsiProc;

    // Represents a list of processes
    typedef struct osi_procs_struct {
        uint32_t num;
        OsiProc *proc;
    } OsiProcs;

    // Represents a single module (userspace library or kernel module)
    typedef struct osi_module_struct {
        target_ulong offset;
        char *file;
        target_ulong base;
        target_ulong size;
        char *name;
    } OsiModule;

    // Represents a list of modules
    typedef struct osi_modules_struct {
        uint32_t num;
        OsiModule *module;
    } OsiModules;
```

Example
-------

The `osi` plugin is not very useful on its own. If you want to see an example of how to use when writing your own plugins, have a look at [osi_test](/panda/plugins/osi_test/).
