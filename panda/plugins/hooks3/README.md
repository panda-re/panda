# hooks3

> So nice we did it thrice.

The hooks3 plugin is a full-TCG hooks implementation.

## Building

To check if the plugin will build:

```
cargo check
```

To actually build the plugin:

```
cargo build --release
```

(remove `--release` if you want to build in debug mode)

The resulting plugin will be located in `target/release/librust_skeleton.so`.

## Structure

```
├── Cargo.toml
├── hooks3.h
├── Makefile
├── README.md
└── src
   └── hooks3.rs
   └── api.rs
   └── hook_manager.rs
```

* Cargo.toml - The core plugin info. This informs `cargo` how to actually go about building the plugin. It includes the name, dependencies, and features of plugins.
* Makefile - Instructions for how the PANDA build system will build the plugin.
* hooks3.h - C compatible API description.
* src/hooks3.rs - The main source file of the plugin. Contains init/uninit and callbacks as well as the "middle_filter" handler for TCG callbacks.
* src/api.rs - This contains a C compatible API
* src/hook_manager.rs - Implements the primary logic for the system.


## API

The hooks3 API is comprised of these functions:

```
unsigned int register_plugin(void);
```

This function returns a unique identifier for your plugin. You will use this identifier to register hooks.


```
void unregister_plugin(unsigned int plugin_id);
```

If you no longer wish to receive callbacks (i.e. at plugin exit) you should call `unregister_plugin`. Calling this function removes all existing callbacks and *guarantees* that your previously registered callbacks will not called. This removes the need to clear the TB cache on program exit.

NOTE: Ensure that `hooks3` is still loaded when you attempt to unregister your plugin. This is important because plugin unloading order at exit is not guaranteed.

```
void add_hook(
    unsigned int plugin_id,     // ID from register_plugin
    target_ulong pc,            // Virtual Address to hook
    target_ulong asid,          // ASID or 0 for any ASID
    bool always_starts_block,   // Guarantee pc starts block (see note)
    FnCb fun                    // Function to be called (see note)
)
```

The `add_hook` function adds a hook to the set of currently evaluated hooks.

NOTE: `always_starts_block` - If you are certain that for your use case that your pc value will start a block this should be set to true. For example, if you plan to hook a library function you would expect a call to the address you hook. If so, this guarantee holds. However, if you plan to hook the middle of a library function you may not be able to guarantee that pc is the start of a block.


## Callback Structure

```
typedef FnCb bool(*)(CPUState* cpu, TranslationBlock* tb, const Hook* h);
```

Unlike previous versions of hooks the `Hook` structure is immutable. Another change is a return type. The callback returns a bool evaluated as `should_hook_be_removed`. Returning true will remove the callback.


## Operation





