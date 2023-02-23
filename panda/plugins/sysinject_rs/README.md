Plugin: sysinject
===========

Summary
------
`sysinject` allows for the injection of syscalls into the guest at arbitrary points. 

The function `inject_syscall` takes 4 arguments
    1) `cpu`, the cpu state. This is standard for panda plugins.
    2) `callno`, the syscall number. This number will vary for each syscall dependant on the cpu architecture of the guest, so make sure that you have the right one.
    3) `nargs`, the number of arguments to your syscall.
    4) `raw_args`, the arguments to pass to your syscall, given as type `target_ulong[nargs]`. From python, you'll want to use `panda.ffi.new("target_ulong[]", arglist])`, where `arglist` is a list of each of your arguments. Likewise, each element in `arglist` will need to be converted from its original type to `target_ulong` through `panda.ffi.cast("target_ulong", orig_arg)`.

To use the plugin, simply put the call to `inject_syscall` where you want it to be triggered. For `mips`, if you are having it triggered at a certain address, you will need to somehow gate the function call to avoid repeated calls, since for that architecture the PC is backed up one instruction at the end of `inject_syscall`.