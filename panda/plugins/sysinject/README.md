Plugin: sysinject
===========

Summary - Raw API
------
`sysinject` allows for the injection of syscalls into the guest at arbitrary points. 

The function `inject_syscall` takes 4 arguments

    1. `cpu`, the cpu state. This is standard for panda plugins.

    2. `callno`, the syscall number. This number will vary for each syscall dependant on the cpu architecture of the guest, so make sure that you have the right one.

    3. `nargs`, the number of arguments to your syscall.

    4. `raw_args`, the arguments to pass to your syscall, given as type `target_ulong[nargs]`. 
         From python, you'll want to use `panda.ffi.new("target_ulong[]", arglist])`, where `arglist` is a list of each of your arguments.
         Likewise, each element in `arglist` will need to be converted from its original type to `target_ulong` through `panda.ffi.cast("target_ulong", orig_arg)`.

To use the plugin, simply put the call to `inject_syscall` where you want it to be triggered. For `mips`, if you are having it triggered at a certain address, you will need to somehow gate the function call to avoid repeated calls, since for that architecture the PC is backed up one instruction at the end of `inject_syscall`.

The function `sys_access` simply wraps `inject_syscall`, which we expect to be a common use of this plugin. It takes two arguments
    1. `cpu`, the cpu state. This is standard for panda plugins.

    2. `raw_args`, the arguments to pass to your syscall, given as type `target_ulong[nargs]`. 
         From python, you'll want to use `panda.ffi.new("target_ulong[]", arglist])`, where `arglist` is a list of each of your arguments.
         Likewise, each element in `arglist` will need to be converted from its original type to `target_ulong` through `panda.ffi.cast("target_ulong", orig_arg)`.

This function can be used identially to `inject_syscall`

Summary - Simplified Interface
------

The functionallity of `sysinject` can be alternately accessed through pypanda (as opposed to directly using the plugin), which offloads the work of casting variables and thinking about the number of arguments. To use `sysinject` this way, simply use `panda.inject_syscall` or `panda.sys_access` instead of `panda.plugins["sysinject"].inject_syscall` or `panda.plugins["sysinject"].sys_access`.

The function `inject_syscall` here instead takes 3 arguments:
    
    1. `cpu`, the cpu state.

    2. `num`, the syscall number.

    3. `args`, a list of arguments to pass to the syscall.

The function `sys_access` here takes 2 arguments:

    1. `cpu`, the cpu state.

    2. `args`, a list of arguments, namely `pathname` and `mode`.



Example
------

The following is small example of how to use this plugin, it functions if you replace `ptr` with an address you know will actually be hit.


```from pandare import Panda
panda = Panda(generic="arm")
@panda.queue_blocking
def run_cmd():
    panda.revert_sync("root")
    // print out the exit code, which should be 0xaa if everything worked
    print(panda.run_serial_cmd('printf "Exit code: %x" $?'))
    panda.end_analysis()

ptr = 0xface0ff

// Hook some known address where we want the syscall to fire
// This hook uses the base plugin interface, which is clunky and likely not what you want,
// but is presented here for completeness
panda.hook(ptr)
def hook(cpu, tb, h):
    // need to cast the arguments to the syscall to types rust can handle, namely *const target_ulong
    raw_args = panda.ffi.new("target_ulong[]", [panda.ffi.cast("target_ulong",0xaa)])
    // call inject_syscall through sysinject, passing: 
    //     cpu 
    //     248 (syscall num for exit_group in arm)
    //     1 (since exit_group takes one argument)
    //     raw_args: the arguments to pass to the syscall, in this case 0xaa since it's a non-standard exit code
    panda.plugins["sysinject"].inject_syscall(cpu, 248, 1, raw_args)

// Only one of this or the previous will actually run, since the syscall is exiting, but both work
panda.hook(ptr)
def hook2(cpu, tb, h):
    // Using this interface, you do not need to do the casting yourself
    // call inject_syscall through panda, passing:
    //     cpu: cpu state
    //     args: list of arguments, in this case just 0xab since it's a non-standard exit code
    panda.inject_syscall(cpu, [0xab])
    
// This hook will call sys_access through the base plugin interface
panda.hook(ptr)
def access(cpu, tb, h):
    raw_args = panda.ffi.new("target_ulong[]", [panda.ffi.cast("target_ulong", 0xfeedbeef), panda.ffi.cast("taret_ulong", 0x0)])
    // call sys_access, passing a pointer to the file name to access (the pointer can instead be used to page in memory containing that address)
    // as well as the mode
    panda.plugins["sysinject"].sys_access(cpu, raw_args)
    
panda.hook(ptr)
def access2(cpu, tb, h):
    // basically the same as the previous hook, with fewer steps
    panda.sys_access(cpu, [0xfeedbeef, 0x0])
    
panda.enable_precise_pc()
panda.disable_tb_chaining()
panda.run()
```

A more complete, runnable, example can be found in `panda/python/examples/sysinject`.
