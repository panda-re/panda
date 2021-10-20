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


