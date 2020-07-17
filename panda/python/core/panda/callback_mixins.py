'''
Mixin for handling callbacks and generation of decorators that allow users to register their own callbacks
such as panda.cb_before_block_exec()
'''
from .utils import progress, make_iso, debug
from .ffi_importer import ffi

class callback_mixins():
    def register_cb_decorators(self):
        '''
        Setup callbacks and generate self.cb_XYZ functions for cb decorators
        XXX Don't add any other methods with names starting with 'cb_'
        Callbacks can be called as @panda.cb_XYZ in which case they'll take default arguments and be named the same as the decorated function
        Or they can be called as @panda.cb_XYZ(name='A', procname='B', enabled=True). Defaults: name is function name, procname=None, enabled=True unless procname set
        '''
        for cb_name, pandatype in zip(self.callback._fields, self.callback):
            def closure(closed_cb_name, closed_pandatype): # Closure on cb_name and pandatype
                def f(*args, **kwargs):
                    if len(args): # Called as @panda.cb_XYZ without ()s- no arguments to decorator but we get the function name instead
                        # Call our decorator with only a name argument ON the function itself
                        fun = args[0]
                        return self._generated_callback(closed_pandatype, **{"name": fun.__name__})(fun)
                    else:
                        # Otherwise, we were called as @panda.cb_XYZ() with potential args - Just return the decorator and it's applied to the function
                        return self._generated_callback(closed_pandatype, *args, **kwargs)
                return f

            setattr(self, 'cb_'+cb_name, closure(cb_name, pandatype))

    def _generated_callback(self, pandatype, name=None, procname=None, enabled=True):
        '''
        Actual implementation of self.cb_XYZ. pandatype is pcb.XYZ
        name must uniquely describe a callback
        if procname is specified, callback will only be enabled when that asid is running (requires OSI support)
        '''

        if procname:
            enabled = False # Process won't be running at time 0 (probably)
            self._register_internal_asid_changed_cb()

        def decorator(fun):
            local_name = name  # We need a new varaible otherwise we have scoping issues with _generated_callback's name
            if name is None:
                local_name = fun.__name__
            def _run_and_catch(*args, **kwargs): # Run function but if it raises an exception, stop panda and raise it
                try:
                    r = fun(*args, **kwargs)
                    #print(pandatype, type(r)) # XXX Can we use pandatype to determine requried return and assert if incorrect
                    #assert(isinstance(r, int)), "Invalid return type?"
                    return r
                except Exception as e:
                    self.end_analysis()
                    print("\n" + "--"*30 + f"\n\nException in callback `{fun.__name__}`: {e}\n")
                    import traceback
                    traceback.print_exc()
                    self.exception = e # XXX: We can't raise here or exn won't fully be printed. Instead, we print it in check_crashed()
                    return # XXX: Some callbacks don't expect returns, but most do. If we don't return we might trigger a separate exn and lose ours (occasionally)
                    # If we return the wrong type, we lose the original exn (TODO)

            cast_rc = pandatype(_run_and_catch)
            self.register_callback(pandatype, cast_rc, local_name, enabled=enabled, procname=procname)
            def wrapper(*args, **kw):
                return _run_and_catch(*args, **kw)
            return wrapper
        return decorator

    def _register_internal_asid_changed_cb(self):
        '''
        Call this function if you need procname filtering for callbacks. It enables
        an internal callback on asid_changed (and sometimes an after_block_exec cb)
        which will deteremine when the process name changes and enable/disable other callbacks
        that filter on process name.
        '''
        if self._registered_asid_changed_internal_cb: # Already registered these callbacks
            return

        @self.callback.after_block_exec
        def __get_pending_procname_change(cpu, tb, exit_code):
            if exit_code: # Didn't actually execute block
                return None
            if not self.in_kernel(cpu): # Once we're out of kernel code, grab procname
                process = self.plugins['osi'].get_current_process(cpu)
                if process != ffi.NULL:
                    name = ffi.string(process.name).decode("utf8", "ignore")
                else:
                    return None # Couldn't figure out the process
                asid = self.libpanda.panda_current_asid(cpu)
                self.asid_mapping[asid] = name
                self.procname_changed(name)
                self.disable_callback('__get_pending_procname_change') # Disabled to begin


        # Local function def
        @self.callback.asid_changed
        def __asid_changed(cpustate, old_asid, new_asid):
            '''
            When the ASID changes, check if we know its procname (in self.asid_mapping),
            if so, call panda.procname_changed(name). Otherwise, we enable __get_pending_procname_change CB, which
            waits until the procname changes. Then we grab the new procname, update self.asid_mapping and call
            panda.procname_changed(name)
            '''
            if old_asid == new_asid:
                return 0

            if new_asid not in self.asid_mapping: # We don't know this ASID->procname - turn on __get_pending_procname_change
                if not self.is_callback_enabled('__get_pending_procname_change'):
                    self.enable_callback('__get_pending_procname_change')
            else: # We do know this ASID->procname, just call procname_changed
                self.procname_changed(self.asid_mapping[new_asid])

            return 0

        self.register_callback(self.callback.asid_changed, __asid_changed, "__asid_changed") # Always call on ASID change

        # This internal callback is only enabled on-demand (later) when we need to figure out ASID->procname mappings
        self.register_callback(self.callback.after_block_exec, __get_pending_procname_change, "__get_pending_procname_change", enabled=False)

        self._registered_asid_changed_internal_cb = True

    def register_callback(self, callback, function, name, enabled=True, procname=None):
        # CB   = self.callback.main_loop_wait
        # func = main_loop_wait_cb
        # name = main_loop_wait

        if name in self.registered_callbacks:
            raise ValueError("Duplicate callback name {}".format(name))

        cb = self.callback_dictionary[callback]

        # Generate a unique handle for each callback type using the number of previously registered CBs of that type added to a constant
        handle = ffi.cast('void *', 0x8888 + 100*len([x for x in self.registered_callbacks.values() if x['callback'] == cb]))

        # XXX: We should have another layer of indirection here so we can catch
        #      exceptions raised during execution of the CB and abort analysis
        pcb = ffi.new("panda_cb *", {cb.name:function})

        if debug:
            progress("Registered function '{}' to run on callback {}".format(name, cb.name))

        self.libpanda.panda_register_callback_helper(handle, cb.number, pcb)
        self.registered_callbacks[name] = {"procname": procname, "enabled": True, "callback": cb,
                           "handle": handle, "pcb": pcb, "function": function} # XXX: if function is not saved here it gets GC'd and everything breaks! Watch out!

        if not enabled: # Note the registered_callbacks dict starts with enabled true and then we update it to false as necessary here
            self.disable_callback(name)

        if "block" in cb.name:
            if not self.disabled_tb_chaining:
                print("Warning: disabling TB chaining to support {} callback".format(cb.name))
                self.disable_tb_chaining()


    def is_callback_enabled(self, name):
        if name not in self.registered_callbacks.keys():
            raise RuntimeError("No callback has been registered with name '{}'".format(name))
        return self.registered_callbacks[name]['enabled']

    def enable_internal_callbacks(self):
        '''
        Enable all our internal callbacks that start with __ such as __main_loop_wait
        and __asid_changed. Important in case user has done a panda.end_analysis()
        and then (re)called run
        '''
        for name in self.registered_callbacks.keys():
            if name.startswith("__") and not self.registered_callbacks[name]['enabled']:
                self.enable_callback(name)

    def enable_all_callbacks(self):
        '''
        Enable all python callbacks that have been disabled
        '''
        for name in self.registered_callbacks.keys():
            self.enable_callback(name)

    def enable_callback(self, name):
        '''
        Enable a panda plugin using its handle and cb.number as a unique ID
        '''
        if name not in self.registered_callbacks.keys():
            raise RuntimeError("No callback has been registered with name '{}'".format(name))

        self.registered_callbacks[name]['enabled'] = True
        handle = self.registered_callbacks[name]['handle']
        cb = self.registered_callbacks[name]['callback']
        pcb = self.registered_callbacks[name]['pcb']
        #progress("Enabling callback '{}' on '{}' handle = {}".format(name, cb.name, handle))
        self.libpanda.panda_enable_callback_helper(handle, cb.number, pcb)

    def disable_callback(self, name, forever=False):
        '''
        Disable a panda plugin using its handle and cb.number as a unique ID
        If forever is specified, we'll never reenable the call- useful when
        you want to really turn off something with a procname filter.
        '''
        if name not in self.registered_callbacks.keys():
            raise RuntimeError("No callback has been registered with name '{}'".format(name))
        self.registered_callbacks[name]['enabled'] = False
        handle = self.registered_callbacks[name]['handle']
        cb = self.registered_callbacks[name]['callback']
        pcb = self.registered_callbacks[name]['pcb']
        #progress("Disabling callback '{}' on '{}' handle={}".format(name, cb.name, handle))
        self.libpanda.panda_disable_callback_helper(handle, cb.number, pcb)

        if forever:
            del self.registered_callbacks[name]

    ###########################
    ### PPP-style callbacks ###
    ###########################

    def ppp(self, plugin_name, attr, name=None):
        '''
        Decorator for plugin-to-plugin interface. Note this isn't in decorators.py
        becuase it uses the panda object.

        Example usage to register my_run with syscalls2 as a 'on_sys_open_return'
        @ppp("syscalls2", "on_sys_open_return")
        def my_fun(cpu, pc, filename, flags, mode):
            ...
        '''

        if plugin_name not in self.plugins: # Could automatically load it?
            print(f"PPP automatically loaded plugin {plugin_name}")

        if not hasattr(self, "ppp_registered_cbs"):
            self.ppp_registered_cbs = {}
            # We use this to traak fn_names->fn_pointers so we can later disable by name

            # XXX: if  we don't save the cffi generated callbacks somewhere in Python,
            # they may get garbage collected even though the c-code could still has a
            # reference to them  which will lead to a crash. If we stop using this to track
            # function names, we need to keep it or something similar to ensure the reference
            # count remains >0 in python

        def decorator(func):
            local_name = name  # We need a new varaible otherwise we have scoping issues, maybe
            if local_name is None:
                local_name = func.__name__
            f = ffi.callback(attr+"_t")(func)  # Wrap the python fn in a c-callback.
            assert (local_name not in self.ppp_registered_cbs), f"Two callbacks with conflicting name: {local_name}"

            # Ensure function isn't garbage collected, and keep the name->(fn, plugin_name, attr) map for disabling
            self.ppp_registered_cbs[local_name] = (f, plugin_name, attr)

            self.plugins[plugin_name].__getattr__("ppp_add_cb_"+attr)(f) # All PPP cbs start with this string
            return f
        return decorator

    def disable_ppp(self, name):
        '''
        Disable a ppp-style callback by name.
        Unlike regular panda callbacks which can be enabled/disabled/deleted, PPP callbacks are only enabled/deleted (which we call disabled)

        Example usage to register my_run with syscalls2 as a 'on_sys_open_return' and then disable:
        @ppp("syscalls2", "on_sys_open_return")
        def my_fun(cpu, pc, filename, flags, mode):
            ...

        panda.disable_ppp("my_fun")

        -- OR --

        @ppp("syscalls2", "on_sys_open_return", name="custom")
        def my_fun(cpu, pc, filename, flags, mode):
            ...

        panda.disable_ppp("custom")
        '''

        (f, plugin_name, attr) = self.ppp_registered_cbs[name]
        self.plugins[plugin_name].__getattr__("ppp_remove_cb_"+attr)(f) # All PPP cbs start with this string
        del self.ppp_registered_cbs[name] # It's now safe to be garbage collected
