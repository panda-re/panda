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

There is no guarantee a kernel sets each value every time. The `struct auv_values` is set to 0 before it is filled. A value provided should be suspect if it is a zero.

Example
-------
