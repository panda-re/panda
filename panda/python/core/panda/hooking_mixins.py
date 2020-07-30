"""
Provides the ability to interact with the hooks2 plugin and receive callbacks based on user-provided criteria.
"""

from .ffi_importer import ffi
from .utils import debug
class Hook(object):
    '''
    Maintains the state of a hook as defined by a user.
    '''
    def __init__(self,is_enabled=True,is_kernel=True,hook_cb=True,target_addr=0,target_library_offset=0,library_name=None,program_name=None):
        self.is_enabled = is_enabled
        self.is_kernel = is_kernel
        self.hook_cb = hook_cb
        self.target_addr = target_addr
        self.target_library_offset = target_library_offset
        self.library_name = library_name
        self.program_name = program_name

class hooking_mixins():
    def update_hook(self,hook_name,addr):
        '''
        Update hook to point to a different addres.
        '''
        if hook_name in self.named_hooks:
            hook = self.named_hooks[hook_name]
            if addr != hook.target_addr:
                hook.target_addr = addr
                self.enable_hook(hook)

    def enable_hook(self,hook_name):
        '''
        Set hook status to active.        
        '''
        if hook_name in self.named_hooks:
            hook = self.named_hooks[hook_name]
            if not hook.is_enabled:
                hook.is_enabled = True
                self.plugins['hooks'].enable_hook(hook.hook_cb, hook.target_addr)

    def disable_hook(self,hook_name):
        '''
        Set hook status to inactive.
        '''
        if hook_name in self.named_hooks:
            hook = self.named_hooks[hook_name]
            if hook.is_enabled:
                hook.is_enabled = False
                self.plugins['hooks'].disable_hook(hook.hook_cb)
        else:
            print(f"{hook_name} not in list of hooks")

    def update_hooks_new_procname(self, name):
        '''
        Uses user-defined information to update the state of hooks based on things such as libraryname, procname and whether 
        or not the hook points to kernel space.
        '''
        for h in self.hook_list:
            if not h.is_kernel and ffi.NULL != current:
                if h.program_name:
                    if h.program_name == curent_name and not h.is_enabled:
                        self.enable_hook(h)
                    elif hook.program_name != current_name and hook.is_enabled:
                        self.disable_hook(h)
                libs = self.get_mappings(cpustate,current)
                if h.library_name:
                    lowest_matching_lib = None
                    if libs == ffi.NULL: continue
                    for i in range(libs.num):
                        lib = libs.module[i]
                        if lib.file != ffi.NULL:
                            filename = ffi.string(lib.file).decode()
                            if h.library_name in filename:
                                if lowest_matching_lib:
                                    lowest_matching_lib = lib if lib.base < lowest_matching_lib.base else lowest_matching_lib
                                else:
                                    lowest_matching_lib = lib
                    if lowest_matching_lib:
                        self.update_hook(h, lowest_matching_lib.base + h.target_library_offset)
                    else:
                        self.disable_hook(h)

    def hook(self, addr, enabled=True, kernel=True, libraryname=None, procname=None, name=None):
        '''
        Decorate a function to setup a hook: when a guest goes to execute a basic block beginning with addr,
        the function will be called with args (CPUState, TranslationBlock)
        '''
        if procname:
            self._register_internal_asid_changed_cb()
        def decorator(fun):
            # Ultimately, our hook resolves as a before_block_exec_invalidate_opt callback so we must match its args
            hook_cb_type = self.callback.before_block_exec_invalidate_opt # (CPUState, TranslationBlock)

            if 'hooks' not in self.plugins:
                # Enable hooks plugin on first request
                self.load_plugin("hooks")

            if debug:
                print("Registering breakpoint at 0x{:x} -> {} == {}".format(addr, fun, 'cdata_cb'))

            # Inform the plugin that it has a new breakpoint at addr
            hook_cb_passed = hook_cb_type(fun)
            self.plugins['hooks'].add_hook(addr, hook_cb_passed)
            hook_to_add = Hook(is_enabled=enabled,is_kernel=kernel,target_addr=addr,library_name=libraryname,program_name=procname,hook_cb=None, target_library_offset=None)
            if libraryname: 
                hook_to_add.target_library_offset = addr
                hook_to_add.target_addr = 0
                hook_to_add.hook_cb = hook_cb_passed
            else:
                hook_to_add.hook_cb = hook_cb_passed
            self.hook_list.append(hook_to_add)
            if name:
                if not hasattr(self, "named_hooks"):
                    self.named_hooks = {}
                self.named_hooks[name] = hook_to_add
            if libraryname or procname:
                self.disable_hook(hook_to_add)

            @hook_cb_type # Make CFFI know it's a callback. Different from _generated_callback for some reason?
            def wrapper(*args, **kw):
                return fun(*args, **kw)

            return wrapper
        return decorator
