Plugin: Hooks
===========

Summary
-------
Plugin to call python functions (via pypanda) before executing code at a given address.

Arguments
---------

Dependencies
------------

When using `add_symbol_hook` `dynamic_symbols` is required.

APIs and Callbacks
------------------

```
void add_hook(struct hook*)
```

This takes a struct hook pointer and enables callbacks as appropriate to provide the right callbacks for the hook.

```
void add_symbol_hook(struct symbol_hook*)
```

Symbol hooks are a different kind of hook. Instead of hooking library addresses they hook symbols: which are an optional library name and symbol name pairing. For example, if you provide "libc" and "_Exit" through the `struct symbol_hook*`, and a callback you will receive callbacks each time "_Exit" is called in "libc" upon future resolution of that symbol. Symbols are hooked for all programs so if unwanted make sure to check the proper program and disable as necessary.

Hook Callbacks
-------------

The hook callbacks are available in several styles. They are essentially the same as the specified callback style, but they also contain a pointer to the relevant hook. For example, if we were to use the `before_block_exec` style it would look like:

```
void (*before_block_exec)(CPUState* env, TranslationBlock* tb, struct hook*);
```

Changes made to the hooks in callbacks are propagated. Hooks disabled are removed.


struct hook
------------

The `hook` struct allows a user to set up a hook on any of several callbacks (see: `hooks_panda_cb`). They may specify the type with the `type` parameter. A basic hook will set a `start_addr` and an `end_addr` which covers a region in which callbacks should be triggered. Users may also specify an `asid` to filter on the basis of or specify that the `asid` is 0 to trigger on all asids. Users may also use `enum kernel_mode` to set `km` to filter on the basis of the kernel mode state. Lastly, users may set the `enable` boolean in the struct. Structs which are disabled after a user has seen them will never be used again and so are removed.

Example
-------
