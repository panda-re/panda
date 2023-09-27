Plugin: CallWithArg
===========

Summary
-------

At every function call, check the first N (potential) arguments to see if any are a specified integer value or a pointer to a specified string value. If so, trigger a custom PPP event.

The goal here is to dynamically identify functions that take a known value as an argument. **Many false positives are to be expected!** But if you test multiple values, you can use this plugin to easily identify a hookable function in a target program to build custom introspection gadgets.

Arguments
---------

`targets`: an `_` seperated list of hex numbers and/or strings to check for (e.g., `0x1234_hello world_0xABCDEF`)
`verbose`: If set to 1, print on every detected call.
`N`: How many arguments to examine. Default 2. Only supports standard linux calling conventions for now.


Dependencies
------------
`callstack_instr`

APIs and Callbacks
------------------
API
* `void add_target_string(char* s)`, `void add_target_num(target_ulong x)`: Add a new target
* `bool remove_target_string(char* s)`, `bool remove_target_num(target_ulong x)`: Remove an existing target. Returns true if the argument was previously a target

Callbacks:
```
on_call_match_num(CPUState *cpu, target_ulong* args, uint matching_idx, uint args_read);
```

```
on_call_match_str(CPUState *cpu, target_ulong* args, uint matching_idx, char* value, uint args_read);
```

Example
-------
```
$(python3 -m pandare.qcows x86_64) -panda callwitharg:targets=root_hello_0x41414141,verbose=1
root@guest# echo hello
root@guest# echo AAAA
root@guest# whoami
```