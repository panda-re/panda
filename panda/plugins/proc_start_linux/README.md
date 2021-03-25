Plugin: proc_start_linux
===========

Summary
-------

This plugin uses `syscalls2` to provide the auxiliary vector in Linux systems as a PPP callback.

Arguments
---------

Dependencies
------------
syscalls2.
APIs and Callbacks
------------------

We provide the following PPP callback:

```
void (*on_rec_auxv_t)(CPUState *env, TranslationBlock *tb, struct auxv_values);
```

The structure currently provides many elements of the auxiliary vector that you are quite unlikely to need.

Example
-------
