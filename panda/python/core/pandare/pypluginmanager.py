#!/usr/bin/env python3

"""
Class to manage loading Panda PyPlugins. See docs/pyplugins.md for details.
"""
from pathlib import Path
from pandare import PyPlugin

class _DotGetter(object):
    '''
    Simple class to provide access to fields via attribute (dot) looukups
    '''
    def __init__(self, data=None):
        if data is None:
            data = {}
        self.data = data

    def set(self, k, v):
        self.data[k] = v

    def __str__(self):
        return str([x for x in self.data.keys()])

    def __getattr__(self, name):
        raise NotImplementedError("Subclass must implement this virtual method")

class _PppFuncs(_DotGetter):
    def __getattr__(self, name):
        method = self.data.get(name, None)
        if method is None:
            raise AttributeError(f"No method {name}: available options are {self}")
        return lambda *args: method(*args)

class _PppPlugins(_DotGetter):
    def __getattr__(self, name):
        plugin = self.data.get(name, None)
        if plugin is None:
            raise AttributeError(f"No plugin named {plugin}")
        return plugin

    def add(self, plugin_name, func_name, func):
        # Create _PppFuncs for plugin_name if necessary
        # store func_name = func in _PppFuncs[plugin_name]
        plugin = self.data.get(plugin_name, None)
        if not plugin:
            self.set(plugin_name, _PppFuncs())
            plugin = self.data.get(plugin_name, None)

        plugin.set(func_name, func)

class PyPluginManager:
    def __init__(self, panda, flask=False, host='127.0.0.1', port=8080, silence_warning=False):
        '''
        Set up an instance of PyPluginManager.
        '''

        self.panda = panda
        self.plugins = {}
        self.silence_warning = silence_warning
        self._ppp_plugins = _PppPlugins()

        self.flask = flask
        self.port  = None
        self.host  = None
        self.app   = None
        self.blueprint    = None
        self.flask_thread = None

        if self.flask:
            self.enable_flask(host, port)

    @property
    def ppp(self):
        return self._ppp_plugins

    def get_ppp_funcs(self, plugin):
        # iterate over each attribute in the class `plugin`
        for item_name in dir(plugin):
            item = getattr(plugin, item_name)
            # check if the class attribute has a field called `__is_pyplugin_ppp`
            #print("CHECK:", item, hasattr(item, "__is_pyplugin_ppp"))
            if hasattr(item, "_PyPlugin__is_pyplugin_ppp") and getattr(item, "_PyPlugin__is_pyplugin_ppp"):
                self.ppp.add(plugin.__class__.__name__, item.__name__, item)

    def enable_flask(self, host='127.0.0.1', port=8080):
        '''
        Enable flask mode for this instance of the PyPlugin manager. Registered PyPlugins
        which support flask will be made available at the web interfaces.
        '''
        if len(self.plugins) and not self.silence_warning:
            print("WARNING: You've previously registered some PyPlugins prior to enabling flask")
            print(f"Plugin(s) {self.plugins.keys()} will be unable to use flask")

        from flask import Flask, Blueprint
        self.flask = True
        self.app = Flask(__name__)
        self.blueprint = Blueprint
        self.host = host
        self.port = port

    def load_plugin_class(self, plugin_file, class_names):
        '''
        For backwards compatability with PyPlugins which subclass
        PyPlugin without importing it.

        Given a path to a python file which has a class that subclasses
        PyPlugin, set up the imports correctly such that we can
        generate an uninstantiated instance of that class and return
        that object.

        Note you can also just add `from pandare import PyPlugin` to
        the plugin file and then just import the class(es) you want and pass them
        directly to panda.pyplugins.register()

        This avoids the `NameError: name 'PyPlugin' is not defined` which
        you would get from directly doing `import [class_name] from [plugin_file]`
        '''
        import importlib.util
        spec = importlib.util.spec_from_file_location(plugin_file.split("/")[-1], plugin_file)
        if spec is None:
            raise ValueError(f"Unable to resolve plugin {plugin_file}")
        plugin = importlib.util.module_from_spec(spec)
        plugin.PyPlugin = PyPlugin
        spec.loader.exec_module(plugin)
        classes = []
        success = False
        for class_name in class_names:
            if not hasattr(plugin, class_name):
                continue

            cls = getattr(plugin, class_name)
            assert issubclass(cls, PyPlugin), f"Class {class_name} does not subclass PyPlugin"
            classes.append(cls)
            success = True

        if not success:
            print(f"Warning: {plugin_file} does not contain any of the requested classes {class_names}")

        return classes

    def load(self, pluginclasses, args=None, template_dir=None):
        '''
        Load (aka register) a PyPANDA plugin  to run. It can later be unloaded
        by using panda.pyplugins.unload(name).

        pluginclasses can either be an uninstantiated python class, a list of such classes,
        or a tuple of (path_to_module.py, [classnames]) where classnames is a list of
        clases subclasses which subclass PyPlugin.

        Each plugin class will be stored in self.plugins under the class name
        '''

        if args is None:
            args = {}

        pluginpath = None
        if isinstance(pluginclasses, tuple):
            # Tuple: use self.load_plugin_class to load the requested classes from
            # the provided file
            pluginpath, clsnames = pluginclasses
            pluginclasses = self.load_plugin_class(pluginpath, clsnames)

        elif not isinstance(pluginclasses, list):
            # Single element: make it a list with one item
            pluginclasses = [pluginclasses]

        # This is a little tricky - we can't just instantiate
        # an instance of the object- it may use self.get_arg
        # in its init method. To allow this behavior, we create
        # the object, use the __preinit__ function defined above
        # and then ultimately call the __init__ method
        # See https://stackoverflow.com/a/6384982/2796854

        for pluginclass in pluginclasses:
            if not isinstance(pluginclass, type) or not issubclass(pluginclass, PyPlugin):
                raise ValueError(f"pluginclass must be an uninstantiated subclass of PyPlugin")

            name = pluginclass.__name__

            self.plugins[name] = pluginclass.__new__(pluginclass)
            self.plugins[name].__preinit__(self, args)
            self.plugins[name].__init__(self.panda)
            self.get_ppp_funcs(self.plugins[name])

            # Setup webserver if necessary
            if self.flask:
                self.plugins[name].flask = self.app

                # If no template_dir was provided, try using ./templates in the dir of the plugin
                # if we know it, otherwise ./templates
                if template_dir is None:
                    if pluginpath is not None:
                        template_dir = (Path(pluginpath).parent / "templates").absolute()
                    elif (Path(".") / "templates").exists():
                        template_dir = (Path(".") / "templates").absolute()
                    else:
                        print("Warning: pyplugin couldn't find a template dir")

                bp = self.blueprint(name, __name__, template_folder=template_dir)
                self.plugins[name].webserver_init(bp)
                self.app.register_blueprint(bp, url_prefix="/" + name)

    def load_all(self, plugin_file, args=None, template_dir=None):
        '''
        Given a path to a python file, load every PyPlugin defind in that file by identifying
        all classes that subclass PyPlugin and passing them to self.load()
        '''
        import inspect, importlib
        spec = importlib.util.spec_from_file_location("snake_hook", plugin_file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        for name, cls in inspect.getmembers(module, lambda x: inspect.isclass(x) and x.__module__ == "snake_hook"): # matches module set above
            self.load(cls, args, template_dir)

    def unload(self, pluginclass):
        if isinstance(pluginclass, str):
            name = pluginclass
        else:
            name = pluginclass.__name__

        del self.plugins[name]

    def unload_all(self):
        # XXX: Why don't we just clear the plugin list? The refcount isn't
        # dropping to zero after the clear and I can't figure out why. So
        # we'll explicitly call __del__ if it exists on unload as per
        # the PyPlugin API
        for instance in self.plugins.values():
            if callable(getattr(instance, "__del__", None)):
                instance.__del__()
        self.plugins.clear()

    def is_loaded(self, pluginclass):
        if isinstance(pluginclass, str):
            name = pluginclass
        else:
            name = pluginclass.__name__
        return name in self.plugins

    def get_plugin(self, pluginclass):
        # Lookup name
        if isinstance(pluginclass, str):
            name = pluginclass
        else:
            name = pluginclass.__name__
        if not self.is_loaded(pluginclass, name):
            raise ValueError(f"Plugin {name} is not loaded")
        return self.plugins[name]


    def serve(self):
        assert(self.flask)
        assert(self.flask_thread is None)
        from threading import Thread
        self.flask_thread = Thread(target=self._do_serve, daemon=True)
        self.flask_thread.start() # TODO: shut down more gracefully?

    def _do_serve(self):
        assert(self.flask)

        @self.app.route("/")
        def index():
            return "PANDA PyPlugin web interface. Available plugins:" + "<br\>".join( \
                    [f"<li><a href='/{name}'>{name}</a></li>" \
                            for name in self.plugins.keys() \
                            if hasattr(self.plugins[name], 'flask')])

        self.app.run(host=self.host, port=self.port)

if __name__ == '__main__':
    from pandare import Panda
    panda = Panda(generic="x86_64")

    globals()['_test_class_init_ran'] = False
    globals()['_test_get_arg_foo'] = False
    globals()['_test_print_hello_false'] = False
    globals()['_test_print_hello2_true'] = False
    globals()['_test_deleted'] = False

    class TestPlugin(PyPlugin):
        def __init__(self, panda):
            path = self.get_arg('path')
            print(f"path = {path}")
            global _test_class_init_ran, _test_get_arg_foo, \
                   _test_print_hello_false, _test_print_hello2_true
            _test_class_init_ran = True
            _test_get_arg_foo = path == "/foo"

            should_print_hello = self.get_arg_bool('should_print_hello')
            if should_print_hello:
                print("Hello!")
            else:
                _test_print_hello_false = True

            should_print_hello2 = self.get_arg_bool('should_print_hello2')
            if should_print_hello2:
                _test_print_hello2_true = True


        def __del__(self):
            global _test_deleted
            _test_deleted = True
    panda.pyplugins.load(TestPlugin, {'path': '/foo', 'should_print_hello': False,
                                                         'should_print_hello2': True})
    @panda.queue_blocking
    def driver():
        panda.revert_sync("root")
        assert(panda.run_serial_cmd("whoami") == 'root'), "Bad guest behavior"
        panda.pyplugins.unload(TestPlugin)
        panda.end_analysis()

    panda.run()

    for k in ['_test_class_init_ran', '_test_print_hello_false', '_test_get_arg_foo',
              '_test_print_hello2_true','_test_deleted']:
        assert(globals()[k] == True), f"Failed test {k}"
