Plugin: proc_start_linux
===========

Summary
-------

This plugin uses `syscalls2` to provide the auxiliary vector in Linux systems as a PPP callback.

Arguments
---------

Dependencies
------------

APIs and Callbacks
------------------

We provide the following PPP callback:

```
void (*on_rec_auxv_t)(CPUState *env, TranslationBlock *tb, struct auxv_values);
```

The structure currently provides:

```
struct auxv_values {
    char procname[MAX_PATH_LEN];
    target_ulong phdr;
    target_ulong entry;
};
```
but can fairly easily be extended to add more.

Example
-------
