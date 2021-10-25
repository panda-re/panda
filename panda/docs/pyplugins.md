# PANDA PyPlugins

PyPlugins are Python3 classes which implement some reusable PANDA capability.

The anatomy of a PANDA PyPlugin in its current form is one or more types which subclass `PandaPlugin`. The constructor takes a `panda` object, which is of type [pandare.Panda](https://docs.panda.re/panda.html#pandare.panda.Panda).

From there, you can add hooks and declare initial state for your plugin. The destructor (`__del__`) is optional, but can be used to perform cleanup when `snake_hook` is unloaded.

## API Docs

* `PandaPlugin`:
  * `get_arg(name)` - returns either the argument value as a string or `None` if the argument is not present
  * `get_arg_bool(name)` - returns `True` if the argument is present and truthy.


# Example Plugins

## Trivial plugin
```py
from pandare import PandaPlugin

class TestPlugin(PandaPlugin):
    def __init__(self, panda):
        print("Initialized test plugin")
        
        @panda.cb_before_block_exec
        def test_before_block(cpustate, transblock):
            print("Running test plugin")
            panda.disable_callback('test_before_block')

    def __del__(self):
        print("Uninitialized test plugin")
```

## Basic block counter
```python
from pandare import PandaPlugin

class BasicBlockCount(PandaPlugin):
    def __init__(self, panda):
        self.bb_count = 0

        @panda.cb_before_block_exec
        def my_before_block_fn(_cpu, _trans):
            self.bb_count += 1

    def webserver_init(self, app):
        @app.route("/")
        def test_index():
            return """<html>
            <body>
                <p>
                    Basic Block Count: <span id="bb_count">""" + str(self.bb_count) +  """</span>
                </p>
            </body>
            </html>"""
```


## Hello
```py
class HelloPlugin(PandaPlugin):
    def __init__(self, panda):
        path = self.get_arg('path')
        print(f"path = {path}")
        should_print_hello = self.get_arg_bool('should_print_hello')
        if should_print_hello:
            print("Hello!")
```

# Example Usage:

## PyPANDA
To use a PyPlugin from a PyPanda script, you should either define it within your python script or import it from another file using the standard Python import mechanisms. Once your plugin class is in scope, you'll register it with the panda.pyplugin object:
```
panda.pyplugin.register(YourPlugin, {'path': '/foo'})
```

For example, if the `Hello` example from above is in the file hello.py and that's in the same directory as your PyPANDA script, you could do:
```
from pandare import Panda
from hello import HelloPlugin
panda = Panda.generic("x86_64")
panda.pyplugin.register(HelloPlugin, {'should_print_hello': True})
```

Note that when the plugin was registered, we also specified an argument `should_print_hello` and set it to True.

## Snake Hook
You can use the [SnakeHook](../plugins/snake_hook) plugin to load a PyPanda plugin from the PANDA command line. For example, if you've created the `hello.py` example as described in the prior section, you could load it with `panda-system-.... -snake_hook:files=./hello`. The snake_hook documentation provides further details on how to load multiple plugins and how to set arguments for each of them.

