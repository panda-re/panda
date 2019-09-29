import sys

if sys.version_info[0] < 3:
    print("Please run with Python 3!")
    sys.exit(0)

import socket
import threading

from os.path import join as pjoin
from os.path import realpath, exists, abspath, isfile

from os import dup, getenv, devnull, environ
from random import randint
from inspect import signature
from tempfile import NamedTemporaryFile

from .taint import TaintQuery

from .autogen.panda_datatypes import * # ffi, pcb come from here
from .panda_expect import Expect
from .asyncthread import AsyncThread
from .images import qcows
from .plog import PLogReader
from .utils import progress, make_iso, debug

# Mixins to extend Panda class functionality
from .libpanda_mixins   import libpanda_mixins
from .blocking_mixins   import blocking_mixins
from .osi_mixins        import osi_mixins
from .hooking_mixins    import hooking_mixins
from .callback_mixins   import callback_mixins
from .taint_mixins      import taint_mixins

import pdb

# location of panda build dir
panda_build = realpath(pjoin(abspath(__file__), "../../../../build"))

class Panda(libpanda_mixins, blocking_mixins, osi_mixins, hooking_mixins, callback_mixins, taint_mixins):
    def __init__(self, arch="i386", mem="128M",
            expect_prompt=None, os_version=None,
            qcow=None, extra_args=[], os="linux", generic=None):

        self.arch = arch
        self.mem = mem
        self.os = os_version
        self.qcow = qcow

        if isinstance(extra_args, str): # Extra args can be a string or array
            extra_args = extra_args.split()

        # If specified use a generic (x86_64, i386, arm, ppc) qcow from moyix and ignore
        if generic:                                 # other args. See details in qcows.py
            q = qcows.get_qcow_info(generic)
            self.arch     = q.arch
            self.os       = q.os
            self.qcow     = qcows.get_qcow(generic)
            expect_prompt = q.prompt
            if q.extra_args:
                extra_args.extend(q.extra_args.split(" "))

        if self.qcow: # Otherwise we shuld be able to do a replay with no qcow but this is probably broken
            #if self.qcow == "default": # Use arch / mem / os to find a qcow - XXX: merge with generic?
            #    self.qcow = pjoin(getenv("HOME"), ".panda", "%s-%s-%s.qcow" % (self.os, self.arch, mem))
            if not (exists(self.qcow)):
                print("Missing qcow '{}' Please go create that qcow and give it to moyix!".format(self.qcow))

        self.bindir = pjoin(panda_build, "%s-softmmu" % self.arch)
        environ["PANDA_PLUGIN_DIR"] = self.bindir+"/panda/plugins" # Set so libpanda can query, see callbacks.c:215
        environ["PANDA_BUILD_DIR"] = panda_build
        self.panda = pjoin(self.bindir, "qemu-system-%s" % self.arch)

        self.libpanda_path = pjoin(self.bindir,"libpanda-%s.so" % self.arch)
        self.libpanda = ffi.dlopen(self.libpanda_path)

        self.bits, self.endianness, self.register_size = self._determine_bits()

        # Setup argv for panda
        biospath = realpath(pjoin(self.panda,"..", "..",  "pc-bios"))
        #self.panda_args = [self.panda, "-m", self.mem, "-display", "none", "-L", biospath]

        self.panda_args = [self.panda, "-L", biospath]

        if self.qcow:
            self.panda_args.append(self.qcow)

        self.panda_args += extra_args

        # Configure serial - Always enabled for now
        self.serial_file = NamedTemporaryFile(prefix="pypanda_s").name
        self.serial_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.serial_console = Expect(expectation=expect_prompt, quiet=True, consume_first=False)
        self.panda_args.extend(['-serial', 'unix:{},server,nowait'.format(self.serial_file)])

        # Configure monitor - Always enabled for now
        self.monitor_file = NamedTemporaryFile(prefix="pypanda_m").name
        self.monitor_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.monitor_console = Expect(expectation="(qemu)", quiet=True, consume_first=True)
        self.panda_args.extend(['-monitor', 'unix:{},server,nowait'.format(self.monitor_file)])

        self.running = threading.Event()
        self.started = threading.Event()
        self.athread = AsyncThread(self.started) # athread manages actions that need to occur outside qemu's CPU loop

        # Callbacks
        self.callback = pcb
        self.register_cb_decorators()
        self.registered_callbacks = {} # name -> {procname: "bash", enabled: False, callback: None}

        # Register asid_changed CB if and only if a callback requires procname
        self._registered_asid_changed_internal_cb = False

        self._initialized_panda = False
        self.disabled_tb_chaining = False
        self.taint_enabled = False
        self.hook_list = []

        # Asid stuff
        self.current_asid_name = None
        self.asid_mapping = {}

        # main_loop_wait functions and callbacks
        self.main_loop_wait_fnargs = [] # [(fn, args), ...]
        progress ("Panda args: [" + (" ".join(self.panda_args)) + "]")
    # /__init__

    def _initialize_panda(self):
        '''
        After initializing the class, the user has a chance to do something
        (TODO: what? register callbacks? It's something important...) before we finish initializing
        '''
        self.libpanda.panda_set_library_mode(True)
        if self.os:
            self.set_os_name(self.os)

        cenvp = ffi.new("char**", ffi.new("char[]", b""))
        len_cargs = ffi.cast("int", len(self.panda_args))
        panda_args_ffi = [ffi.new("char[]", bytes(str(i),"utf-8")) for i in self.panda_args]
        self.libpanda.panda_init(len_cargs, panda_args_ffi, cenvp)

        # Now we've run qemu init so we can connect to the sockets for the monitor and serial
        if not self.serial_console.is_connected():
            self.serial_socket.connect(self.serial_file)
            self.serial_console.connect(self.serial_socket)
        if not self.monitor_console.is_connected():
            self.monitor_socket.connect(self.monitor_file)
            self.monitor_console.connect(self.monitor_socket)

        # Register __main_loop_wait_callback
        self.register_callback(self.callback.main_loop_wait,
                self.callback.main_loop_wait(self.__main_loop_wait_cb), '__main_loop_wait')

        self._initialized_panda = True

    def _determine_bits(self):
        '''
        Given self.arch, determine bits, endianness and register_size
        '''
        bits = None
        endianness = None # String 'little' or 'big'
        if self.arch == "i386":
            bits = 32
            endianness = 'little'
        elif self.arch == "x86_64":
            bits = 64
            endianness = 'little'
        elif self.arch == "arm":
            endianness = 'little' # XXX add support for arm BE
            bits = 32
        elif self.arch == "aarch64":
            bit = 64
        elif self.arch == "ppc":
            bits = 32

        assert (bits is not None), "For arch %s: I need logic to figure out num bits" % self.arch
        assert (endianness is not None), "For arch %s: I need logic to figure out endianness" % self.arch
        register_size = int(bits/8)

        return bits, endianness, register_size

    def __main_loop_wait_cb(self):
        '''
        __main_loop_wait_cb is called at the start of the main cpu loop in qemu.
        This is a fairly safe place to call into qemu internals but watch out for deadlocks caused
        by your request blocking on the guest's execution. Here any functions in main_loop_wait_fnargs will be called
        '''
        # Then run any and all requested commands
        if len(self.main_loop_wait_fnargs) == 0: return
        #progress("Entering main_loop_wait_cb")
        for fnargs in self.main_loop_wait_fnargs:
            (fn, args) = fnargs
            ret = fn(*args)
        self.main_loop_wait_fnargs = []


    def queue_main_loop_wait_fn(self, fn, args=[]):
        '''
        Queue a function to run at the next main loop
        fn is a function we want to run, args are arguments to apss to it
        '''
        self.main_loop_wait_fnargs.append((fn, args))

    def exit_cpu_loop(self):
        self.libpanda.panda_break_cpu_loop_req = True

    def revert(self, snapshot_name): # In the next main loop, revert
        if debug:
            progress ("Loading snapshot " + snapshot_name)

            # Stop guest, queue up revert, then continue
            self.vm_stop()
            charptr = ffi.new("char[]", bytes(snapshot_name, "utf-8"))
            self.queue_main_loop_wait_fn(self.libpanda.panda_revert, [charptr])
            self.queue_main_loop_wait_fn(self.libpanda.panda_cont)

    def cont(self): # Continue execution (run after vm_stop)
        self.libpanda.panda_cont()
        self.running.set()

    def vm_stop(self, code=4): # Stop execution, default code means RUN_STATE_PAUSED
        self.libpanda.panda_stop(code)

    def snap(self, snapshot_name):
        if debug:
            progress ("Creating snapshot " + snapshot_name)

        # Stop guest execution, queue up a snapshot, then continue
        self.vm_stop()
        charptr = ffi.new("char[]", bytes(snapshot_name, "utf-8"))
        self.queue_main_loop_wait_fn(self.libpanda.panda_snap, [charptr])
        self.queue_main_loop_wait_fn(self.libpanda.panda_cont)

    def delvm(self, snapshot_name):
        if debug:
            progress ("Deleting snapshot " + snapshot_name)

        # Stop guest, queue up delete, then continue
        self.vm_stop()
        charptr = ffi.new("char[]", bytes(snapshot_name, "utf-8"))
        self.queue_main_loop_wait_fn(self.libpanda.panda_delvm, [charptr])


    def enable_tb_chaining(self):
        if debug:
            progress("Enabling TB chaining")
        self.disabled_tb_chaining = False
        self.libpanda.panda_enable_tb_chaining()

    def disable_tb_chaining(self):
        if not self.disabled_tb_chaining:
            if debug:
                progress("Disabling TB chaining")
            self.disabled_tb_chaining = True
            self.libpanda.panda_disable_tb_chaining()

    def run(self):
        if debug:
            progress ("Running")

        if not self._initialized_panda:
            self._initialize_panda()

        if not self.started.is_set():
            self.started.set()

        # Ensure our internal CBs are always enabled
        self.enable_internal_callbacks()

        self.running.set()
        self.libpanda.panda_run() # Give control to panda
        self.running.clear() # Back from panda's execution (due to shutdown or monitor quit)

    def end_analysis(self):
        '''
        Call from any thread to unload all plugins. If called from async thread, it will also
        unblock panda.run()
        '''
        self.unload_plugins()
        if self.running:
            self.queue_async(self.stop_run)

    def run_replay(self, replaypfx):
        '''
        Load a replay and run it
        '''
        if not isfile(replaypfx+"-rr-snp") or not isfile(replaypfx+"-rr-nondet.log"):
            raise ValueError("Replay files not present to run replay of {}".format(replaypfx))
        
        if debug:
            progress ("Replaying %s" % replaypfx)

        charptr = ffi.new("char[]",bytes(replaypfx,"utf-8"))
        self.libpanda.panda_replay(charptr)
        self.run()

    def require(self, name):
        '''
        Load a C plugin with no arguments. Deprecated. Use load_plugin
        '''
        self.load_plugin(name, args={})

    def load_plugin(self, name, args={}):
        '''
        Load a C plugin, optionally with arguments
        '''
        if debug:
            progress ("Loading plugin %s" % name),

        argstrs_ffi = []
        if isinstance(args, dict):
            for k,v in args.items():
                this_arg_s = "{}={}".format(k,v)
                this_arg = ffi.new("char[]", bytes(this_arg_s, "utf-8"))
                argstrs_ffi.append(this_arg)

            n = len(args.keys())
        elif isinstance(args, list):
            for arg in args:
                this_arg = ffi.new("char[]", bytes(arg, "utf-8"))
                argstrs_ffi.append(this_arg)
            n = len(args)

        else:
            raise ValueError("Arguments to load plugin must be a list or dict of key/value pairs")

        # First set qemu_path so plugins can load (may be unnecessary after the first time)
        panda_name_ffi = ffi.new("char[]", bytes(self.panda,"utf-8"))
        self.libpanda.panda_set_qemu_path(panda_name_ffi)

        charptr = pyp.new("char[]", bytes(name,"utf-8"))
        self.libpanda.panda_require_from_library(charptr)
        self.load_plugin_library(name)

    def procname_changed(self, name):
        for cb_name, cb in self.registered_callbacks.items():
            if not cb["procname"]:
                continue
            if name == cb["procname"] and not cb['enabled']:
                self.enable_callback(cb_name)
            if name != cb["procname"] and cb['enabled']:
                self.disable_callback(cb_name)

            self.update_hooks_new_procname(name)

    def unload_plugin(self, name):
        if debug:
            progress ("Unloading plugin %s" % name),
        name_ffi = ffi.new("char[]", bytes(name,"utf-8"))
        self.libpanda.panda_unload_plugin_by_name(name_ffi)

    def unload_plugins(self):
        if debug:
            progress ("Unloading all panda plugins")

        # First unload python plugins, should be safe to do anytime
        for name in self.registered_callbacks.keys():
            self.disable_callback(name)

        # Then unload C plugins. May be unsafe to do except from the top of the main loop (taint segfaults otherwise)
        self.queue_main_loop_wait_fn(self.libpanda.panda_unload_plugins)

    def rr_get_guest_instr_count(self):
        return self.libpanda.rr_get_guest_instr_count_external()

    def memsavep(self, file_out):
        newfd = dup(f_out.fileno())
        self.libpanda.panda_memsavep(newfd)
        self.libpanda.fclose(newfd)

    def current_sp(self, cpustate): # under construction
        if self.arch == "i386":
            from x86.helper import R_ESP
            return cpustate.env_ptr.regs[R_ESP]
        else:
            raise NotImplemented("current_sp doesn't yet support arch {}".format(self.arch))

    def virtual_memory_read(self, env, addr, length, fmt='bytearray'):
        '''
        Read but with an autogen'd buffer. Returns a bytearray
        '''
        if not hasattr(self, "_memcb"):
            self.enable_memcb()
        buf = ffi.new("char[]", length)

        buf_a = ffi.cast("char*", buf)
        length_a = ffi.cast("int", length)
        self.libpanda.panda_virtual_memory_read_external(env, addr, buf_a, length_a)

        r = ffi.unpack(buf, length)
        if fmt == 'bytearray':
            return r
        elif fmt=='int':
            return int.from_bytes(r, byteorder=self.endianness)  # XXX size better be small enough to pack into an int!
        elif fmt=='str':
            return ffi.string(buf, length)
        else:
            raise ValueError("fmt={} unsupported".format(fmt))


    def virtual_memory_write(self, env, addr, buf, length):
        # XXX: Should update to automatically build buffer
        if not hasattr(self, "_memcb"):
            self.enable_memcb()
        return self.libpanda.panda_virtual_memory_write_external(env, addr, buf, length)

    def callstack_callers(self, lim, cpu): # XXX move into new directory, 'callstack' ?
        if not hasattr(self, "libpanda_callstack_instr"):
            progress("enabling callstack_instr plugin")
            self.require("callstack_instr")
        
        callers = ffi.new("uint32_t[%d]" % lim)
        n = self.libpanda_callstack_instr.get_callers(callers, lim, cpu)
        c = []
        for pc in callers:
            c.append(pc)
        return c

    def load_plugin_library(self, name):
        if hasattr(self,"__did_load_libpanda"):
            libpanda_path_chr = ffi.new("char[]",bytes(self.libpanda_path,"UTF-8"))
            self.__did_load_libpanda = self.libpanda.panda_load_libpanda(libpanda_path_chr)
        libname = "libpanda_%s" % name
        if not hasattr(self, libname):
            assert(isfile(pjoin(self.bindir, "panda/plugins/panda_%s.so"% name)))
            library = ffi.dlopen(pjoin(self.bindir, "panda/plugins/panda_%s.so"% name))
            self.__setattr__(libname, library)

    def get_cpu(self,cpustate):
        if self.arch == "arm":
            return self.get_cpu_arm(cpustate)
        elif self.arch == "x86":
            return self.get_cpu_x86(cpustate)
        elif self.arch == "x64" or self.arch == "x86_64":
            return self.get_cpu_x64(cpustate)
        elif self.arch == "ppc":
            return self.get_cpu_ppc(cpustate)
        else:
            return self.get_cpu_x86(cpustate)

    # note: should add something to check arch in self.arch
    def get_cpu_x86(self,cpustate):
        # we dont do this because x86 is the assumed arch
        # ffi.cdef(open("./include/panda_x86_support.h")) 
        return ffi.cast("CPUX86State*", cpustate.env_ptr)

    def get_cpu_x64(self,cpustate):
        # we dont do this because x86 is the assumed arch
        if not hasattr(self, "x64_support"):
            self.x64_support = ffi.cdef(open("./include/panda_x64_support.h").read()) 
        return ffi.cast("CPUX64State*", cpustate.env_ptr)

    def get_cpu_arm(self,cpustate):
        if not hasattr(self, "arm_support"):
            self.arm_support = ffi.cdef(open("./include/panda_arm_support.h").read())
        return ffi.cast("CPUARMState*", cpustate.env_ptr)

    def get_cpu_ppc(self,cpustate):
        if not hasattr(self, "ppc_support"):
            self.ppc_support = ffi.cdef(open("./include/panda_ppc_support.h").read())
        return ffi.cast("CPUPPCState*", cpustate.env_ptr)

    def queue_async(self, f):
        self.athread.queue(f)

# vim: expandtab:tabstop=4:
