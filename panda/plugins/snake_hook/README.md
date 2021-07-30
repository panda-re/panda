# snake_hook

A plugin for running pypanda scripts in a plugin-style architecture. Unlike traditional pypanda usage, this allows PANDA to drive python, rather than python driving PANDA. This allows for a higher level of uncoordinated composability than is possible from using pypanda itself.

### Example Usage

```
panda-system-x86_64 -panda snake_hook:files=print_pcs.py:print_strings.py -nographic
```

### Arguments

* `files` - a colon-separated list of python files to load

### Example Plugin

```py
class TestPlugin(PandaPlugin):
    def __init__(self, panda):
        print("Initialized test plugin")
        
        @panda.cb_before_block_exec
        def before_block(cpustate, transblock):
            panda.unload_plugin("snake_hook")
            print("snake_hook unloaded")

    def __del__(self):
        print("Uninitialized test plugin")
```

The anatomy of a pypanda plugin in its current form is one or more types which subclass `PandaPlugin` (`PandaPlugin` is a type that will already be in scope). The constructor takes a `panda` object, which is of type [pandare.Panda](https://docs.panda.re/panda.html#pandare.panda.Panda).

From there, you can add hooks and declare initial state for your plugin. The destructor (`__del__`) is optional, but can be used to perform cleanup when `snake_hook` is unloaded.
