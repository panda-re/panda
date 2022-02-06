# Fault Hooks

Get a notification when a fault causes memory of interest to be paged in.

## API

The fault_hooks API is comprised of these functions:

```
unsigned int fault_hooks_register_plugin(void);
```

This function returns a unique identifier for your plugin. You will use this identifier to register hooks.


```
void fault_hooks_unregister_plugin(unsigned int plugin_id);
```

If you no longer wish to receive callbacks (i.e. at plugin exit) you should call `unregister_plugin`. Calling this function removes all existing callbacks and *guarantees* that your previously registered callbacks will not called. This removes the possibility of a callback being called after your plugin has been unloaded.

NOTE: Ensure that `fault_hooks` is still loaded when you attempt to unregister your plugin. This is important because plugin unloading order at exit is not guaranteed.

```
void fault_hooks_add_hook(
    unsigned int plugin_id,     // ID from register_plugin
    target_ulong page_addr,     // Virtual Address to hook
    target_ulong asid,          // ASID (must be provided)
    FaultHookCb fun             // Function to be called (see note)
)
```

The `fault_hooks_add_hook` function adds a hook to the set of currently evaluated hooks.

NOTE: You may provide a hook for any address in a given page, but the callback will return the address of the page mapped in.

## Callback Structure

```
typedef FaultHookCb void(*)(CPUState* cpu, target_ulong asid, target_ulong page_addr);
```

## Design

The functionality of this plugin is quite simple. It sets a callback on exceptions as they occur. If they are cause by a page fault we enable a callback that waits for user space to run and then checks that the page is still mapped. If it is mapped then we notify the user.