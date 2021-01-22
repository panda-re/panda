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

You may alternatively get a callback when a specified symbol has been resolved. 


Example
-------
