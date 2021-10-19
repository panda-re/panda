#!/usr/bin/env python3

"""
Class to manage loading PyPANDA plugins of standard format
which is compatable with the snake_hook plugin for CLI-panda
"""

class PandaPlugin:
    def __init__(self, panda):
        '''
        Base class which PyPANDA plugins should inherit. Subclasses may
        register callbacks using the provided panda object and use
        PandaPlugin.get_args or PandaPlugin.get_arg_bool to check argument
        values (note these helpers should be accessed with `self.get_...`).

        This PyPANDA extra aims to mirror the snake_hook (rust) plugin
        so a single PyPANDA plugin can be used from both pure PyPANDA (with this class)
        or from CLI panda with snake_hook.

        For more information, read the snake_hook documentation
        '''
        pass

    def __preinit__(self, args):
        self.args = args

    def get_arg(self, arg_name):
        '''
        returns either the argument as a string or None if the argument
        wasn't passed (arguments passed in bool form (i.e., set but with no value)
        instead of key/value form will also return None).
        '''
        if arg_name in self.args:
            return self.args[arg_name]

        return None

    def get_arg_bool(self, arg_name):
        '''
        returns True if the argument is True
        '''
        return arg_name in self.args and self.args[arg_name]==True


class Snake:
    def __init__(self, panda, flask=False, port=8080, host='127.0.0.1'):
        '''
        panda- a panda object
        flask - a bool indicating whether to enable the flask server
        port - a number (0-65535) indicating the port number to host the flask server at
                (default: 8080)
        host - host for flask server to listen on
        '''
        self.panda = panda
        self.plugins = {}

        # Flask specific vars
        self.flask = flask
        self.port = port
        self.host=host
        self.flask_thread = None
        self.app = None
        self.blueprint = None

        if self.flask:
            from flask import Flask, Blueprint
            self.app = Flask(__name__)
            self.blueprint = Blueprint

    def register(self, pluginclass, args=None, name=None):
        '''
        Register a PyPANDA plugin  to run. It can later be unloaded
        by using Snake.unregister(name). If name is unspecified, a
        string representation of the class will be used instead
        '''

        if args is None:
            args = {}
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
            bp = self.blueprint(name, __name__)
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
        print("Started thread")
        assert(self.flask)

        @self.app.route("/")
        def index():
            return "PANDA web server"

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
    s = Snake(panda)
    s.register(TestPlugin, {'path': '/foo', 'should_print_hello': False,
                                            'should_print_hello2': True})
    @panda.queue_blocking
    def driver():
        panda.revert_sync("root")
        assert(panda.run_serial_cmd("whoami") == 'root'), "Bad guest behavior"
        s.unregister(TestPlugin)
        panda.end_analysis()

    panda.run()

    for k in ['_test_class_init_ran', '_test_print_hello_false', '_test_get_arg_foo',
              '_test_print_hello2_true','_test_deleted']:
        assert(globals()[k] == True), f"Failed test {k}"
