# PANDA PyPlugins

PyPlugins are Python3 classes which implement some reusable PANDA capability.

The anatomy of a PANDA PyPlugin in its current form is one or more types which subclass `PandaPlugin`. The constructor takes a `panda` object, which is of type [pandare.Panda](https://docs.panda.re/panda.html#pandare.panda.Panda).

From there, you can add hooks and declare initial state for your plugin. The destructor (`__del__`) is optional, but can be used to perform cleanup when `snake_hook` is unloaded.

## API Docs

* `PandaPlugin`:
  * `get_arg(name)` - returns either the argument value as a string or `None` if the argument is not present
  * `get_arg_bool(name)` - returns `True` if the argument is present and truthy.


# Examples

## Trivial plugin
```py
from pandare import PandaPlugin

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
class TestPlugin(PandaPlugin):
    def __init__(self, panda):
        path = self.get_arg('path')
        print(f"path = {path}")
        should_print_hello = self.get_arg_bool('should_print_hello')
        if should_print_hello:
            print("Hello!")
```
