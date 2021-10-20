# snake_hook

A compiled plugin for running [PyPlugins](/panda/docs/pyplugins.md) Unlike traditional pypanda usage, this allows PANDA to drive python, rather than python driving PANDA. This allows for a higher level of uncoordinated composability than is possible from using pypanda itself.

### Example Usage

```
panda-system-x86_64 -panda snake_hook:files=print_pcs.py:print_strings.py -nographic
```

### Arguments

* `files` - a colon-separated list of python files to load\*
* `stdout` - path for unix socket to redirect stdout to (default: don't redirect stdout)
* `classes` - colon-separated list of classes to execute, defaults to all classes
* `flask` - a bool (0 or 1) indicating whether to enable the flask server
* `port` - a number (0-65535) indicating the port number to host the flask server at (default: 8080)

\*See 'passing arguments to plugins' for more info

### PyPlugins

See [docs/pyplugins.md](/panda/docs/pyplugins.md) for examples and details of PyPlugins.

Note that when `snake_hook` is unloaded, it will call a destructor if you have defined one in your class.

### Flask Integration

Example PyPANDA Plugins can be found in the [pypanda-plugins](https://github.com/panda-re/pypanda-plugins) repository, [in the plugins folder](https://github.com/panda-re/pypanda-plugins/tree/main/plugins).

Each plugin can host its own endpoints under `localhost:port/[plugin_name]` by means of declaring a `webpage_init(app)` then writing a flask application using `app` as normal. In order to mount all plugin-specifc routes under `/[plugin_name]/` the variable `app` is a [`Blueprint`](https://flask.palletsprojects.com/en/2.0.x/blueprints/). If you need access to the `Flask` object itself, use `self.flask` (`flask` is a member of the `PandaPlugin` class).

Note: `plugin_name` is the class name of the subclass of `PandaPlugin`. So a plugin such as:

```python
class BasicBlockCount(PandaPlugin):
    ...
```

Will be mounted at `https://localhost:8080/BasicBlockCount` by default.

### Passing Arguments to Plugins

Arguments passed to pypanda plugins via `snake_hook` take the form of `file_path.py|arg=value|bool_arg|arg2=val`, where `|` separates arguments, arguments themselves take the form of `key=value` (or for bool args, just `key` for true, alternatively '1', 'yes', 'y', and 'true' are all accepted as truthy).

#### API Docs

* `PandaPlugin`
  * `get_arg(name)` - returns either the argument as a string or `None` if the argument wasn't passed (arguments passed in bool form instead of key/value form will also return `None`)
  * `get_arg_bool(name)` - returns `True` if the argument is truthy (either by passing the argument with no value, or with a value of any of the following: '1', 'yes', 'y', 'true'), otherwise returns `False`

#### Snake_hook examples
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
