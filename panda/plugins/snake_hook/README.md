# snake_hook

A plugin for running pypanda scripts in a plugin-style architecture. Unlike traditional pypanda usage, this allows PANDA to drive python, rather than python driving PANDA. This allows for a higher level of uncoordinated composability than is possible from using pypanda itself.

### Example Usage

```
panda-system-x86_64 -panda snake_hook:files=print_pcs.py:print_strings.py -nographic
```

### Arguments

* `files` - a colon-separated list of python files to load\*
* `stdout` - path for unix socket to redirect stdout to (default: don't redirect stdout)
* `classes` - colon-separated list of classes to execute, defaults to all classes

\*See 'passing arguments to plugins' for more info

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

### Passing Arguments to Plugins

Arguments passed to pypanda plugins take the form of `file_path.py|arg=value|bool_arg|arg2=val`, where `|` separates arguments, arguments themselves take the form of `key=value` (or for bool args, just `key` for true, alternatively '1', 'yes', 'y', and 'true' are all accepted as truthy).

#### API Docs

* `PandaPlugin`
  * `get_arg(name)` - returns either the argument as a string or `None` if the argument wasn't passed (arguments passed in bool form instead of key/value form will also return `None`)
  * `get_arg_bool(name)` - returns `True` if the argument is truthy (either by passing the argument with no value, or with a value of any of the following: '1', 'yes', 'y', 'true'), otherwise returns `False`

#### Example

```py
class TestPlugin(PandaPlugin):
    def __init__(self, panda):
        path = self.get_arg('path')
        print(f"path = {path}")
        should_print_hello = self.get_arg_bool('should_print_hello')
        if should_print_hello:
            print("Hello!")
```

First up, passing no arguments to this yields:

```
$ x86_64-softmmu/panda-system-x86_64 -panda snake_hook:files=test.py -nographic

path = None
```

However if we provide a path we get...

```
$ x86_64-softmmu/panda-system-x86_64 -panda "snake_hook:files=test.py|path=/usr/bin" -nographic

path = /usr/bin
```

And now if we add `should_print_hello` with no value:

```
$ x86_64-softmmu/panda-system-x86_64 -panda "snake_hook:files=test.py|path=/usr/bin|should_print_hello" -nographic

path = /usr/bin
Hello!
```

And if we pass 1 (or 'yes'/'y'/'true') we'll get the same thing:

```
$ x86_64-softmmu/panda-system-x86_64 -panda "snake_hook:files=test.py|path=/usr/bin|should_print_hello=1" -nographic

path = /usr/bin
Hello!

$ x86_64-softmmu/panda-system-x86_64 -panda "snake_hook:files=test.py|path=/usr/bin|should_print_hello=false" -nographic

path = /usr/bin
```
