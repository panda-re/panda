System call tracer plugin
====
Generating system call introspection
----
The system call plugin includes a python script named `android_syscall_parser.py`.
This script reads in system call prototypes from a text file, one per line, as a space delimited syscall number and prototype
(see `android_arm_prototypes.txt`).

For Android/Linux, we've implemented a python program that reads kernel source code and outputs a C program that uses kernel
headers to print out the system call prototypes and numbers, with some fixups for calls such as `clone()` which have complicated
semantics that differ between the libc call and system call, and also differ across architectures.

PPP
----
Once a system call number and prototype list has been parsed and code has been generated, other plugins can
register callbacks using PPP for syscall and sysret sites.
The callback-registering plugin can `#include syscalls_ext_typedefs.h`, which defines the function signatures of before/after callbacks
for each system call.
The quickest reference for the list of available callback names is syscall_ppp_register.cpp, which is
included in `syscalls.cpp`.
Callbacks, whether at the call or return site,
take the CPUState, pc, and all of the arguments to the system call.
Any pointers are of type `target_ulong`, and it is the callback's job to dereference/resolve the data.

Alternatively, funtionality which is linked directly into the syscalls plugin can instead register a C++ callback for the
syscall site and. There are two major differences from the externally-available C callbacks:
1. C++ callbacks take a `syscalls::string` object instead of a `target_ulong` for `char*` arguments to the system call, which transparently attempts to load the string from memory each time it is accessed by the plugin, until the dereference is successful
2. to register callbacks for the return sites, the C++ callback for the call site must marshall all the information it requires into an instance of a subclass of `CallbackData` and register a new `ReturnPoint`. This marshalled data may include a `syscalls::string` object.

### Implementation details

For each system call, there are the following program elements:

- a typedef for callbacks at the system call site (`on_<syscall>_t`)
- a typedef for callbacks at the system call return site (`on_<syscall>_return_t`)
- a C array of the system call typedef
- a C array of the system call return typedef
- a C++ vector of std::functions which are callbacks at the system call site
- a C++ function in namespace syscalls that adds a callback to the vector, named `syscalls::register_<syscall>()`
- a C++ struct containing all info the return site callback needs, which is a subclass of the `CallbackData` class
- a C++ function `Callback_RC <syscall>_returned()` that takes the callback data, unpacks it, and calls each C return site callback with the arguments
- a C++ function `syscall::call_<syscall>_callback()` which is called after the C call site callbacks and is passed all the syscall arguments. It passes them to each callback in the vector of callbacks, and if there are any C return site callbacks for that syscall, creates a `CallbackData` with all the arguments, and registers the return site.

The last generated code component is a dispatch table which handles each system call, extracts all the arguments,
calls all the registered C call site callbacks with the arguments, and calls the C++ `syscalls::call_<syscall>_callback()`
function with the arguments.

#### Memory management

System call data waiting for the syscall to return exists in a `ReturnPoint` object in a C++ vector.
The `ReturnPoint` is initially created on the stack and is passed to `appendReturnPoint()` using move semantics.
No data in it is ever copied, and when it is removed from the vector its destructor is called, cleaning up its data.
The `CallbackData` contained in the `ReturnPoint` is constructed using new (see any of the `syscall::call_X_callback()` functions
in `default_callbacks.cpp`), and passed to `ReturnPoint`'s constructor, where it is encapsulated in a `std::unique_ptr`
smart pointer. It will then be deleted when the `ReturnPoint` is destroyed when it is removed from the vector.
