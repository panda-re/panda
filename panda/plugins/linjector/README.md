# linjector

linjector is a PANDA plugin responsible for non-cooperatively injecting a binary into
a linux guest. This process is done via system call injection, chaining system calls
together in order to run the provided executable. It is not recommended to use this directly, but rather to use `guest_plugin_manager` in order to spawn your executable as a child of the PANDA-provided guest agent (`guest_daemon`).

### Arguments

* `guest_binary` - string, the path of the executable to load into the guest
* `proc_name` - string, the process name to inject into. Defaults to `[any]`.
* `require_root` - bool, whether or not to require the process being injected into to have a UID of root
