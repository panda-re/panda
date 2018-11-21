# Plugin: osi

## Summary
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

## Command Line Arguments
  * `os`: The target os. This argument is validated against a list of regular expressions in [common.c][common.c]. For linux, the specified os must also match an existing kernel profile. See [osi_linux documentation][osi_linux_usage] for details.

  ```C
  const char * valid_os_re[] = {
      "windows[-_]32[-_]xpsp[23]",
      "windows[-_]32[-_]7",
      "windows[-_]32[-_]2000",
      "linux[-_]32[-_].+",
      "linux[-_]64[-_].+",
      NULL
  };
  ```

## Dependencies
Depends on some OS-specific plugin to register callbacks that implement the various APIs OSI exposes. Otherwise, any call to OSI will simply fail to return any useful data, as the OSI plugin itself does not know anything about specific operating systems.

## Data Interface

### Data types
The following data structures are defined in the [`osi_types.h` header][osi_types] and for use by the PANDA OSI framework:

```C
    // Represents a process handle
    typedef struct osi_prochandle_struct {
        target_ptr_t taskd;
        target_ptr_t asid;
    } OsiProcHandle;

    // Represents a thread
    typedef struct osi_thread_struct {
        target_pid_t pid;
        target_pid_t tid;
    } OsiThread;

    // Represents a page of memory (not implemented so far)
    typedef struct osi_page_struct {
        target_ptr_t start;
        target_ulong len;
    } OsiPage;

    // Represents a single module (userspace library or kernel module)
    typedef struct osi_module_struct {
        target_ptr_t modd;
        target_ptr_t base;
        target_ptr_t size;
        char *file;
        char *name;
    } OsiModule;

    // Represents a single process
    typedef struct osi_proc_struct {
        target_ptr_t taskd;
        target_ptr_t asid;
        target_pid_t pid;
        target_pid_t ppid;
        char *name;
        OsiPage *pages;     // TODO in osi_linux
    } OsiProc;

```

### Data allocation
When PANDA OSI plugins need a dynamically allocated/freed, it is recommended to use one of [GLib allocation functions][galloc]. This offloads a lot of boilerplate checks (e.g. aborting when an allocation fails) to GLib, which results in more compact plugin code.

In addition to simple allocation, GLib also offers functions that address some common allocation-related anti-patterns. E.g. when dynamically constructing strings, using [`g_strdup_printf`][gstrdupp] helps to avoid the common fallback of using `snprintf` on a static-sized buffer, and typically ommiting checking if the buffer was long enough.

**Note:** Currently, the GLib allocation functions use the vanilla `malloc` internally. So mixing `g_alloc`/`g_free` with `malloc`/`free` should not be a problem. However, when given the opportunity, code should be updated to us the GLib allocation functions for the sake of uniformity.

### Data containers
Some interfaces provided by the PANDA OSI framework require the exchange of *collections* of the base data structures listed above. To avoid reimplementing staple ADTs for this purpose, PANDA OSI framework currently relies on the [container types provided by GLib][gdtypes]. Currently, only [`GArray`][garray] is used when needed to return multiple `OsiProc` or `OsiModule` structs.

Implementations of API calls that use data containers are expected to follow the following rules for the used GLib containers.:

  * Typically, a double pointer (e.g. `GArray **out`) is passed to the OSI API function implementation. The value of `*out` is expected to either be NULL or point to a valid container.
  * In the former case (`*out == NULL`), the implementation is expected to allocate and populate a new container. In case where the container supports setting a free function for its elements, the function has to be set appropriately (e.g. using `g_array_set_clear_func`).
  * In the latter case (`*out != NULL`), the implementation is expected to add values to the pointed container.
  * In case the implementation encounters an error, it is expected to free the container and its contents and set it to NULL (`*out = NULL`) before returning.

Implementation behaviour: The implementation should create and populate a [`GArray`][garray] filled with `OsiProc` elements and set the element-content free function using `g_array_set_clear_func`. The returned data have to be freed using the respective `GArray` deallocation function.

**Note:** The use of GLib containers is for their external interfaces. Internally, OSI plugins may choose to use any type of container it is found to be convenient.

## APIs and Callbacks

To implement OS-specific introspection support, an OSI provider should register the following callbacks:

---

Name: **on\_get\_processes**

Signature:

```C
typedef void (*on_get_processes_t)(CPUState *, GArray **)
```

Description: Retrieves the process list from the guest OS, along with detailed information for each process. to get the process list from the guest OS.

Implementation behaviour: The implementation should populate a [`GArray`][garray] filled with `OsiProc` elements, following the rules described in the *data containers* section above. Results need to be freed using [`g_array_free`][gafree].

---

Name: **on\_get\_process\_handles**

Signature:

```C
typedef void (*on_get_process_handles_t)(CPUState *, GArray **)
```

Description: Retrieves an array of minimal handles of type `OsiProcHandle` for the processes of the guest OS. Using the process list from the guest OS. The minimal handles contain just enough information to (a) uniquely identify a process and (b) retrieve the full process information when needed. This allows for lightweight tracking of processes.

Implementation behaviour: The implementation should populate a [`GArray`][garray] filled with `OsiProcHandle` elements, following the rules described in the *data containers* section above. Results need to be freed using [`g_array_free`][gafree].

---

Name: **on\_get\_current\_process**

Signature:

```C
typedef void (*on_get_current_process_t)(CPUState *, OsiProc **)
```

Description: Called to get the currently running process in the guest OS. The implementation should allocate memory and fill in the pointer to an `OsiProc` struct. The returned `OsiProc` can be freed with `free_osiproc`.

---

Name: **on\_get\_process**

Signature:

```C
typedef void (*on_get_process_t)(CPUState *, OsiProcHandle *, OsiProc **)
```

Description: Called to retrieve full process information about the process pointed to by `OsiProcHandle`. Implementation should allocate memory and fill in the pointer to an `OsiProc` struct. The returned `OsiProc` can be freed with `free_osiproc`.

---

Name: **on\_get\_current\_thread**

Signature:

```C
typedef void (*on_get_current_thread_t)(CPUState *, OsiThread **)
```

Description: Called to retrieve the current thread from the guest OS. The implementation should allocate memory and fill in the pointer to an `OsiThread` struct. The returned `OsiThread` can be freed with `free_osithread`.

---

Name: **on\_get\_modules**

Signature:

```C
typedef void (*on_get_modules_t)(CPUState *, GArray **)
```

Description: Retrieves the kernel modules loaded in the guest OS, along with detailed information for each process. to get the process list from the guest OS.

Implementation behaviour: The implementation should populate a [`GArray`][garray] filled with `OsiModule` elements, following the rules described in the *data containers* section above. Results need to be freed using [`g_array_free`][gafree].

---

Name: **on\_get\_libraries**

Signature:

```C
typedef void (*on_get_libraries_t)(CPUState *, OsiProc *, GArray**)
```

Description: Retrieves the shared libraries loaded for the specified process of the guest OS. The process `OsiProc` can be aquired via a previous call to `on_get_current_process` or `on_get_processes`.

Implementation behaviour: The implementation should populate a [`GArray`][garray] filled with `OsiModule` elements, following the rules described in the *data containers* section above. Results need to be freed using [`g_array_free`][gafree].

<!--
(to be removed)

In addition, there are two callbacks intended to be used by `osi` *users*, rather than by introspection providers:

---

Name: **on\_process\_start**

Signature:

```C
typedef void (*on_process_start_t)(CPUState *, OsiProc *)
```

Description: Called whenever a new process is created in the guest. Passes in an `OsiProc` identifying the newly created process.
This callback is **disabled by default** because it requires a fair amount of computation.
To enable/use this callback you need to have used the `-DOSI_PROC_EVENTS` flag at compile time.

---

Name: **on\_process\_end**

Signature:

```C
typedef void (*on_process_end_t)(CPUState *, OsiProc *)
```

Description: Called whenever a process exits in the guest. Passes in an `OsiProc` identifying the process that just exited.
This callback is **disabled by default** because it requires a fair amount of computation.
To enable/use this callback you need to have used the `-DOSI_PROC_EVENTS` flag at compile time.
-->

## Example
The `osi` plugin is not very useful on its own. If you want to see an example of how to use when writing your own plugins, have a look at [osi_test](/panda/plugins/osi_test/).


<!-- place all urls here -->
[common.c]: /panda/src/common.c
[osi_types]: /panda/plugins/osi/osi_types.h
[osi_linux_usage]: /panda/plugins/osi_linux/USAGE.md
[garray]: https://developer.gnome.org/glib/stable/glib-Arrays.html
[gdtypes]: https://developer.gnome.org/glib/stable/glib-data-types.html
[galloc]: https://developer.gnome.org/glib/stable/glib-Memory-Allocation.html
[gstrdupp]: https://developer.gnome.org/glib/stable/glib-String-Utility-Functions.html#g-strdup-printf
[gafree]: https://developer.gnome.org/glib/stable/glib-Arrays.html#g-array-free

