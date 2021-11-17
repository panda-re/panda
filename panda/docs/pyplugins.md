# PANDA PyPlugins

PyPlugins are Python3 classes which implement some reusable PANDA capability.

The anatomy of a PANDA PyPlugin in its current form is one or more types which subclass `PyPlugin`. The constructor takes a `panda` object, which is of type [pandare.Panda](https://docs.panda.re/panda.html#pandare.panda.Panda).

From there, you can add hooks and declare initial state for your plugin. The destructor (`__del__`) is optional, but can be used to perform cleanup when your plugin is unloaded.

## Relevant API Docs

PyPlugin class which PyPlugins should subclass: [auto generated documentation](https://docs.panda.re/panda_plugin.html).
* `class PyPlugin`:
  * `get_arg(name)` - returns either the argument value as a string or `None` if the argument is not present
  * `get_arg_bool(name)` - returns `True` if the argument is present and truthy.
  * `ppp_cb_boilerplate('ppp_cb_name')`: Define ppp-callback which will be triggered somewhere else in your pyplugin that other pyplugins can register callbacks with.
  * `ppp_run_cb('ppp_cb_name', *args)`: Trigger a previously defind PPP-style callback named `ppp_cb_name` in this plugin with `args`. Any other plugins which have registered a function to run on this callback will be run.
  * `ppp_export`: Static decorator to indicate that a function should be callable by other PyPlugins (Use with `@PyPlugin.ppp_export`, not `@self.ppp_export`)

  * `ppp`: attribute to use for interactions with other PyPlugins, both for ppp-exported functions and ppp-callbacks:
  * `ppp.TargetPlugin.ppp_reg_cb('ppp_cb_name', self.my_func)`: Register the local function `self.my_func` with the PyPlugin `TargetPlugin`'s `ppp_cb_name` ppp-style callback. Note that the target plugin must have previously been loaded.
  * `ppp.TargetPlugin.some_function(*args)`: Call the ppp-exported `some_function` defined in `TargetPlugin`. Note that the target plugin must have previously been loaded.

PyPluginManager: Interface to load/unload PyPlugins with an instance of the `pandare` class, accessable via the `.pyplugin` field of a panda object: [documentation](https://docs.panda.re/pyplugin.html#pandare.PyPluginManager).

# Example Plugins

## Trivial plugin
```py
from pandare import PyPlugin

class TestPlugin(PyPlugin):
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
from pandare import PyPlugin

class BasicBlockCount(PyPlugin):
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
class HelloPlugin(PyPlugin):
    def __init__(self, panda):
        path = self.get_arg('path')
        print(f"path = {path}")
        should_print_hello = self.get_arg_bool('should_print_hello')
        if should_print_hello:
            print("Hello!")
```

## PPP Callbacks
```py
class Server(PyPlugin):
    '''
    PyPlugin which provides a PPP-style callback: `some_f` which is run once at the next BBE callback.
    '''
    def __init__(self, panda):
        self.ppp_cb_boilerplate('some_f') # Inform the world that Server.some_f is a PPP callback

        @panda.cb_before_block_exec
        def server_bbe(cpu, tb):
            print("Server is running all registered `some_f` callbacks")

            self.ppp_run_cb('some_f', panda.current_pc(cpu)) # Run cbs registered to run with Server.some_f: args are current_pc

            panda.disable_callback('server_bbe')

class Consumer(PyPlugin):
    '''
    PyPlugin which defines a function to run when Server's `some_f` callback is triggered
    '''
    def __init__(self, panda):
        self.ppp.Server.ppp_reg_cb('some_f', self.my_f)
        print(f"Calling Server's do_add(1): ", self.call_ppp('Server', 'do_add', 1))

    def my_f(self, arg):
        print("Consumer my_f runs with arg:", hex(arg))
```

## PPP Direct Calls
```py
from pandare import PyPlugin
class Server(PyPlugin):
    '''
    PyPlugin which provides a PPP-exported function do_add which increments a number
    '''
    def __init__(self, panda):
      self.counter = 0

    @PyPlugin.ppp_export
    def do_add(x):
        self.counter += x
        return self.counter

class Consumer(PyPlugin):
    '''
    PyPlugin which calls a function in Server
    '''
    def __init__(self, panda):
        print(f"Calling Server's do_add(1): ", self.ppp.Server.do_add(1))
  ```

# Example Usage:

## PyPANDA
To use a PyPlugin from a PyPanda script, you should either define it within your python script or import it from another file using the standard Python import mechanisms. Once your plugin class is in scope, you'll load it with the panda.pyplugins object:
```py
panda.pyplugins.load(YourPlugin, {'path': '/foo'})
```

For example, if the `Hello` example from above is in the file hello.py and that's in the same directory as your PyPANDA script, you could do:
```py
from pandare import Panda
from hello import HelloPlugin
panda = Panda.generic("x86_64")
panda.pyplugins.load(HelloPlugin, {'should_print_hello': True})
```

You can also load plugins from file paths, for example if `/tmp/plugin.py` contains `class YourPlugin(PyPlugin)` and `class AnotherPlugin(PyPlugin)` and these use the argument `path`, you can:

Load just `YourPlugin`:
```py
panda.pyplugins.load(("/tmp/plugin.py", "YourPlugin"), {'path': '/foo'})
```

Load both plugins:
```py
panda.pyplugins.load(("/tmp/plugin.py", ["YourPlugin", "AnotherPlugin"]), {'path': '/foo'})
```

Load all plugins:
```py
panda.pyplugins.load_all("/tmp/plugin.py", {'path': '/foo'})
```

## Snake Hook
You can use the [SnakeHook](../plugins/snake_hook) plugin to load a PyPanda plugin from the PANDA command line. For example, if you've created the `hello.py` example as described in the prior section, you could load it with `panda-system-.... -snake_hook:files=./hello.py`. The snake_hook documentation provides further details on how to load multiple plugins, specific classes from files, and how to set arguments for each of them.
