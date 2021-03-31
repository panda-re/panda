Plugin: dynamic_symbols
===========

Summary
-------

This plugin looks up and maintains the dynamic symbols from shared objects in memory in linux.

Arguments
---------
None
Dependencies
------------
osi
osi_linux

APIs and Callbacks
------------------

```C
struct symbol resolve_symbol(CPUState* cpu, target_ulong asid, char* section_name, char* symbol);
```

The `resolve_symbol` function is the core of the dynamic_symbols plugin. It resolves the symbol within a particular ASID. The section name search filters by substring (e.g. "libc" will match "libc.so.1"). The symbol search filter must match exactly.

```C
void hook_symbol_resolution(struct symbol_hook *h)
```

Thorough `hook_symbol_resolution` you may get a callback when a specified symbol has been resolved. This is used when `hooks` wants a future resolved symbol to hook on.

```C
struct symbol get_best_matching_symbol(CPUState* cpu, target_ulong address, target_ulong asid);
```

This function attempts to return the *best* matching symbol. This is, generally, the closest symbol without going over. Use at your own risk. It's a best guess. Unless address is the same as PC it could be a different function. It also could be the next block in the function. We don't have a way of knowing.

Example
-------
