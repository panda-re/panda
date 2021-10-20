#!/usr/bin/env python3

"""
Class to manage loading Panda PyPlugins. See docs/pyplugins.md for details.
"""
from pathlib import Path
from pandare import PandaPlugin

class PyPluginManager:
    def __init__(self, panda, flask=False, host='127.0.0.1', port=8080, silence_warning=False):
        '''
        Set up an instance of PyPluginManager.
        '''

        self.panda = panda
        self.plugins = {}
        self.silence_warning = silence_warning

        self.flask = flask
        self.port  = None
        self.host  = None
        self.app   = None
        self.blueprint    = None
        self.flask_thread = None

        if self.flask:
            self.enable_flask(host, port)

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

    def load_plugin_class(self, plugin_file, class_name):
        '''
        For backwards compatability with PyPlugins which subclass
        PandaPlugin without importing it.

        Given a path to a python file which has a class that subclasses
        PandaPlugin, set up the imports correctly such that we can
        generate an uninstantiated instance of that class and return
        that object.

        Note you can also just add `from pandare import PandaPlugin` to
        the plugin file and then just import the class(es) you want and pass them
        directly to panda.pyplugin.register()

        This avoids the `NameError: name 'PandaPlugin' is not defined` which
        you would get from directly doing `import [class_name] from [plugin_file]`
        '''
        import importlib.util
        spec = importlib.util.spec_from_file_location(plugin_file.split("/")[-1], plugin_file)
        if spec is None:
            raise ValueError(f"Unable to resolve plugin {plugin_file}")
        plugin = importlib.util.module_from_spec(spec)
        plugin.PandaPlugin = PandaPlugin
        spec.loader.exec_module(plugin)
        if not hasattr(plugin, class_name):
            raise ValueError(f"Unable to find class {class_name} in {plugin_file}")
        cls = getattr(plugin, class_name)
        assert issubclass(cls, PandaPlugin), f"Class {class_name} does not subclass PandaPlugin"
        return cls

    def register(self, pluginclass, args=None, name=None, template_dir=None):
        '''
        Register a PyPANDA plugin  to run. It can later be unloaded
        by using panda.pyplugin.unregister(name).

        pluginclass can either be an uninstantiated python class
        or a tuple of (path_to_module.py, classname) where classname subclasses PandaPlugin.

        If name is unspecified, a string representation of the class will be used instead
        '''

        if args is None:
            args = {}

        pluginpath = None
        if isinstance(pluginclass, tuple):
            pluginpath, clsname = pluginclass
            pluginclass = self.load_plugin_class(pluginpath, clsname)

        # This is a little tricky - we can't just instantiate
        # an instance of the object- it may use self.get_arg
        # in its init method. To allow this behavior, we create
        # the object, use the __preinit__ function defined above
        # and then ultimately call the __init__ method
        # See https://stackoverflow.com/a/6384982/2796854

        if not isinstance(pluginclass, type) or not issubclass(pluginclass, PandaPlugin):
            raise ValueError(f"pluginclass must be an uninstantiated subclass of PandaPlugin")

        if name is None:
            name = pluginclass.__name__ 

        self.plugins[name] = pluginclass.__new__(pluginclass)
        self.plugins[name].__preinit__(args)
        self.plugins[name].__init__(self.panda)

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

    def unregister(self, pluginclass, name=None):
        if name is None:
            name = pluginclass.__name__ 
        del self.plugins[name]

    def is_registered(self, pluginclass, name=None):
        if name is None:
            name = pluginclass.__name__ 
        return name in self.plugins

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

    class TestPlugin(PandaPlugin):
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
    panda.pyplugin.register(TestPlugin, {'path': '/foo', 'should_print_hello': False,
                                                         'should_print_hello2': True})
    @panda.queue_blocking
    def driver():
        panda.revert_sync("root")
        assert(panda.run_serial_cmd("whoami") == 'root'), "Bad guest behavior"
        panda.pyplugin.unregister(TestPlugin)
        panda.end_analysis()

    panda.run()

    for k in ['_test_class_init_ran', '_test_print_hello_false', '_test_get_arg_foo',
              '_test_print_hello2_true','_test_deleted']:
        assert(globals()[k] == True), f"Failed test {k}"
