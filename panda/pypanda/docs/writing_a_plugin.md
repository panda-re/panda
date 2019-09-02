# Writing a python plugin

In looking at this guide it would be a good idea to follow along with the
[example_plugin.py](../example_plugin.py) file. 

## Initialize the Panda class

The `Panda` class takes many arguments, but the only crucial argument is a
specificed qcow image. If you wish to get started quickly you may use the
[qcows.py](../qcows.py) interface to download a default image and run it.

For example:

```
q = qcows("i386") # pass architecture string
panda = Panda(qcow=q)
```

## Write an `init` method

```
@panda.callback.init
def init(handle):
	# register your callbacks
	# call setup methods
	return True
```

The intialization function must always have the `panda.callback.init` decorator
and return True.

### Register callbacks in `init`

A callback can be registered by calling:

```
panda.register_callback(handle, panda.callback.callback_type, callback_method)
```

It takes the handle to the plugin, passed as an argument to init, a callback
type, and a callback method to be called.

## Load a python plugin

A python plugin can be initialized with an init method and a name as follows:

```
panda.load_python_plugin(init_method, "name_of_plugin")
```

## Running pypanda

### Run from startup

Running a virtual machine from startup is simple:

```
panda.run()
```

### Begin a replay

Running an emulator from a recording is also simple:

```
panda.begin_replay("/path/to/recording")
panda.run()
```

