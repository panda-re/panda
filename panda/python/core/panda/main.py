import sys


if sys.version_info[0] < 3:
    print("Please run with Python 3!")
    sys.exit(0)

import socket
import threading

from os.path import realpath, exists, abspath, isfile, dirname, join as pjoin
from os import dup, getenv, devnull, environ
from random import randint
from inspect import signature
from tempfile import NamedTemporaryFile
from time import time
from math import ceil

from .ffi_importer import ffi
from .taint import TaintQuery
from .panda_expect import Expect
from .asyncthread import AsyncThread
from .images import qcows
from .plog import PLogReader
from .utils import progress, make_iso, debug
from .plugin_list import plugin_list

# Mixins to extend Panda class functionality
from .libpanda_mixins   import libpanda_mixins
from .blocking_mixins   import blocking_mixins
from .osi_mixins        import osi_mixins
from .hooking_mixins    import hooking_mixins
from .callback_mixins   import callback_mixins
from .taint_mixins      import taint_mixins
from .volatility_mixins import volatility_mixins
from .pyperiph_mixins   import pyperipheral_mixins
from .gdb_mixins        import gdb_mixins

import pdb

class Panda(libpanda_mixins, blocking_mixins, osi_mixins, hooking_mixins, callback_mixins, taint_mixins, volatility_mixins, pyperipheral_mixins, gdb_mixins):
    def __init__(self, arch="i386", mem="128M",
            expect_prompt=None, # Regular expression describing the prompt exposed by the guest on a serial console. Used so we know when a running command has finished with its output
            os_version=None,
            qcow=None, # Qcow file to load
            os="linux",
            generic=None, # Helper: specify a generic qcow to use and set other arguments. Supported values: arm/ppc/x86_64/i386. Will download qcow automatically
            raw_monitor = False, # When set, don't specify a -monitor. arg Allows for use of -nographic in args with ctrl-A+C for interactive qemu prompt.
            extra_args=[]):
        self.arch = arch
        self.mem = mem
        self.os = os_version
        self.os_type = os
        self.qcow = qcow
        self.plugins = plugin_list(self)
        self.expect_prompt = expect_prompt

        if isinstance(extra_args, str): # Extra args can be a string or array
            extra_args = extra_args.split()

        # If specified use a generic (x86_64, i386, arm, ppc) qcow from moyix and ignore
        if generic:                                 # other args. See details in qcows.py
            print("using generic " +str(generic))
            q = qcows.get_qcow_info(generic)
            self.arch     = q.arch
            self.os       = q.os
            self.qcow     = qcows.get_qcow(generic)
            self.expect_prompt = q.prompt
            if q.extra_args:
                extra_args.extend(q.extra_args.split(" "))

        if self.qcow: # Otherwise we shuld be able to do a replay with no qcow but this is probably broken
            #if self.qcow == "default": # Use arch / mem / os to find a qcow - XXX: merge with generic?
            #    self.qcow = pjoin(getenv("HOME"), ".panda", "%s-%s-%s.qcow" % (self.os, self.arch, mem))
            if not (exists(self.qcow)):
                print("Missing qcow '{}' Please go create that qcow and give it to moyix!".format(self.qcow))

        self.build_dir  = self._find_build_dir()
        environ["PANDA_DIR"] = self.build_dir
        self.libpanda_path = pjoin(self.build_dir, "{0}-softmmu/libpanda-{0}.so".format(self.arch))
        self.panda = self.libpanda_path # Necessary for realpath to work inside core-panda, may cause issues?
        #self.panda = pjoin(self.build_dir, "{0}-softmmu/panda-system-{0}".format(self.arch)) # Path to binary

        self.bits, self.endianness, self.register_size = self._determine_bits()
        self._do_types_import()
        self.libpanda = ffi.dlopen(self.libpanda_path)

        # set OS name if we have one
        if self.os:
            self.set_os_name(self.os)

        # Setup argv for panda
        self.panda_args = [self.panda]
        biospath = realpath(pjoin(self.build_dir, "pc-bios")) # XXX: necessary for network drivers for arm, so 'pc-bios' is a misleading name
        self.panda_args.append("-L")
        self.panda_args.append(biospath)

        if self.qcow:
            self.panda_args.append(self.qcow)

        self.panda_args += extra_args

        # Configure memory options
        self.panda_args.extend(['-m', mem])

        # Configure serial - if we have an expect_prompt set. Otherwise how can we know what guest cmds are outputting?
        if self.expect_prompt:
            self.serial_file = NamedTemporaryFile(prefix="pypanda_s").name
            self.serial_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.serial_console = Expect(expectation=self.expect_prompt, quiet=True, consume_first=False)
            self.panda_args.extend(['-serial', 'unix:{},server,nowait'.format(self.serial_file)])
        else:
            self.serial_file = None
            self.serial_socket = None
            self.serial_console = None

        # Configure monitor - Always enabled for now
        self.monitor_file = NamedTemporaryFile(prefix="pypanda_m").name
        self.monitor_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.raw_monitor = raw_monitor
        if not self.raw_monitor:
            self.monitor_console = Expect(expectation=rb"(qemu)", quiet=True, consume_first=True)
            self.panda_args.extend(['-monitor', 'unix:{},server,nowait'.format(self.monitor_file)])

        self.running = threading.Event()
        self.started = threading.Event()
        self.athread = AsyncThread(self.started) # athread manages actions that need to occur outside qemu's CPU loop

        # Callbacks
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

        # Shutdown stuff
        self.exception = None # When set to an exn, we'll raise and exit

        # main_loop_wait functions and callbacks
        self.main_loop_wait_fnargs = [] # [(fn, args), ...]
        progress ("Panda args: [" + (" ".join(self.panda_args)) + "]")
    # /__init__

    def _do_types_import(self):
        # Import objects from panda_datatypes which are configured by the environment variables
        # Store these objects in self.callback and self.callback_dictionary

        # There is almost certainly a better way to do this.
        environ["PANDA_BITS"] = str(self.bits)
        environ["PANDA_ARCH"] = self.arch
        from .autogen.panda_datatypes import pcb, C, callback_dictionary # XXX: What is C and do we need it?
        self.callback_dictionary = callback_dictionary
        self.callback = pcb

    def _initialize_panda(self):
        '''
        After initializing the class, the user has a chance to do something
        (TODO: what? register callbacks? It's something important...) before we finish initializing
        '''
        self.libpanda._panda_set_library_mode(True)

        cenvp = ffi.new("char**", ffi.new("char[]", b""))
        len_cargs = ffi.cast("int", len(self.panda_args))
        panda_args_ffi = [ffi.new("char[]", bytes(str(i),"utf-8")) for i in self.panda_args]
        self.libpanda.panda_init(len_cargs, panda_args_ffi, cenvp)

        # Now we've run qemu init so we can connect to the sockets for the monitor and serial
        if self.serial_console and not self.serial_console.is_connected():
            self.serial_socket.connect(self.serial_file)
            self.serial_console.connect(self.serial_socket)
        if not self.raw_monitor and not self.monitor_console.is_connected():
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
            endianness = "little"
        elif self.arch == "x86_64":
            bits = 64
            endianness = "little"
        elif self.arch == "arm":
            endianness = "little" # XXX add support for arm BE?
            bits = 32
        elif self.arch == "aarch64":
            bit = 64
            endianness = "little" # XXX add support for arm BE?
        elif self.arch == "ppc":
            bits = 32
            endianness = "big"
        elif self.arch == "mips":
            bits = 32
            endianness = "big"
        elif self.arch == "mipsel":
            bits = 32
            endianness = "little"

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
        try:
            # Then run any and all requested commands
            if len(self.main_loop_wait_fnargs) == 0: return
            #progress("Entering main_loop_wait_cb")
            for fnargs in self.main_loop_wait_fnargs:
                (fn, args) = fnargs
                ret = fn(*args)
            self.main_loop_wait_fnargs = []
        except KeyboardInterrupt:
            self.end_analysis()

    def _find_build_dir(self):
        '''
        Find build directory containing ARCH-softmmu/libpanda-ARCH.so and ARCH-softmmu/panda/plugins/
        1) check relative to file (in the case of installed packages)
        2) Check in../ ../../../build/
        3) raise RuntimeError
        '''
        archs = ['i386', 'x86_64', 'arm', 'ppc']
        python_package = pjoin(*[dirname(__file__), "data"])
        local_build = realpath(pjoin(dirname(__file__), "../../../../build"))
        path_end = "{0}-softmmu/libpanda-{0}.so".format(self.arch)

        pot_paths = [python_package, local_build]
        for potential_path in pot_paths:
            if isfile(pjoin(potential_path, path_end)):
                print("Loading libpanda from {}".format(potential_path))
                return potential_path

        searched_paths = "\n".join(["\t"+p for p in  pot_paths])
        raise RuntimeError(("Couldn't find libpanda-{}.so.\n"
                            "Did you built PANDA for this architecture?\n"
                            "Searched paths:\n{}"
                           ).format(self.arch, searched_paths))


    def queue_main_loop_wait_fn(self, fn, args=[]):
        '''
        Queue a function to run at the next main loop
        fn is a function we want to run, args are arguments to apss to it
        '''
        self.main_loop_wait_fnargs.append((fn, args))

    def exit_cpu_loop(self):
        self.libpanda.panda_exit_loop = True

    def revert_async(self, snapshot_name): # In the next main loop, revert
        '''
        Request a snapshot revert, eventually. This is fairly dangerous
        because you don't know when it finishes. You should be using revert_sync
        from a blocking function instead
        '''
        print("WARNING: panda.revert_async may be deprecated in the near future")
        if debug:
            progress ("Loading snapshot " + snapshot_name)

        # Stop guest, queue up revert, then continue
        timer_start = time()
        self.vm_stop()
        charptr = ffi.new("char[]", bytes(snapshot_name, "utf-8"))
        self.queue_main_loop_wait_fn(self.libpanda.panda_revert, [charptr])
        self.queue_main_loop_wait_fn(self.libpanda.panda_cont)
        if debug:
            self.queue_main_loop_wait_fn(self.finish_timer, [timer_start, "Loaded snapshot"])

    def reset(self): # In the next main loop, reset to boot
        if debug:
            progress ("Resetting machine to start state")

        # Stop guest, queue up revert, then continue
        self.vm_stop()
        self.queue_main_loop_wait_fn(self.libpanda.panda_reset)
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
        timer_start = time()
        self.vm_stop()
        charptr = ffi.new("char[]", bytes(snapshot_name, "utf-8"))
        self.queue_main_loop_wait_fn(self.libpanda.panda_snap, [charptr])
        self.queue_main_loop_wait_fn(self.libpanda.panda_cont)
        if debug:
            self.queue_main_loop_wait_fn(self.finish_timer, [timer_start, "Saved snapshot"])

    def delvm(self, snapshot_name):
        if debug:
            progress ("Deleting snapshot " + snapshot_name)

        # Stop guest, queue up delete, then continue
        self.vm_stop()
        charptr = ffi.new("char[]", bytes(snapshot_name, "utf-8"))
        self.queue_main_loop_wait_fn(self.libpanda.panda_delvm, [charptr])

    def finish_timer(self, start, msg):
        '''
        Print how long some (main_loop_wait) task took
        '''
        t = time() - start
        print("{} in {1:.08f} seconds".format(msg, t))


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
        '''
        Start execution of guest. Blocks until guest finishes.
        Initializes panda object, clears main_loop_wait fns, sets up internal callbacks
        '''

        if len(self.main_loop_wait_fnargs):
            if debug:
                print("Clearing prior main_loop_wait fns:", self.main_loop_wait_fnargs)
            self.main_loop_wait_fnargs = [] # [(fn, args), ...]

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
        self.libpanda.panda_unload_plugins() # Unload c plugins - should be safe now since exec has stopped

    def end_analysis(self):
        '''
        Call from any thread to unload all plugins and stop all queued functions.
        If called from async thread or a callback, it will also unblock panda.run()

        Note here we use the async class's internal thread to process these
        without needing to wait for tasks in the main async thread
        '''
        self.unload_plugins()
        if self.running.is_set():
            # If we were running, stop the execution and check if we crashed
            self.queue_async(self.stop_run, internal=True)
            self.queue_async(self.check_crashed, internal=True)

    def run_replay(self, replaypfx):
        '''
        Load a replay and run it
        '''
        if not isfile(replaypfx+"-rr-snp") or not isfile(replaypfx+"-rr-nondet.log"):
            raise ValueError("Replay files not present to run replay of {}".format(replaypfx))

        if debug:
            progress ("Replaying %s" % replaypfx)

        charptr = ffi.new("char[]",bytes(replaypfx,"utf-8"))
        self.libpanda.panda_replay_begin(charptr)
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
        assert(self.panda), "Unknown location of PANDA"
        panda_name_ffi = ffi.new("char[]", bytes(self.panda,"utf-8"))
        self.libpanda.panda_set_qemu_path(panda_name_ffi)

        if len(argstrs_ffi):
            plugin_args = argstrs_ffi
        else:
            plugin_args = ffi.NULL

        charptr = ffi.new("char[]", bytes(name,"utf-8"))
        self.libpanda.panda_require_from_library(charptr, plugin_args, len(argstrs_ffi))
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
        '''
        Disable all python plugins and request to unload all c plugins
        at the next main_loop_wait.

        XXX: If called during shutdown/exit, c plugins won't be unloaded
        because the next main_loop_wait will never happen. Instead, call
        panda.panda_finish directly (which is done at the end of panda.run())
        '''
        if debug:
            progress ("Disabling all python plugins, unloading all C plugins")

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
            # XXX see far more complex logic in panda/include/panda/common.h
            from panda.x86.helper import R_ESP
            return cpustate.env_ptr.regs[R_ESP]
        elif self.arch == "arm":
            from panda.arm.helper import R_SP
            return cpustate.env_ptr.regs[R_SP]
        else:
            raise NotImplemented("current_sp doesn't yet support arch {}".format(self.arch))

    def physical_memory_read(self, addr, length, fmt='bytearray'):
        return self._memory_read(None, addr, length, physical=True, fmt=fmt)

    def virtual_memory_read(self, env, addr, length, fmt='bytearray'):
        return self._memory_read(env, addr, length, physical=False, fmt=fmt)

    def _memory_read(self, env, addr, length, physical=False, fmt='bytearray'):
        '''
        Read but with an autogen'd buffer. Returns a tuple (data, error code)
        Supports physical or virtual addresses
        Error code is 0 on success, negative on failure
        '''
        if not hasattr(self, "_memcb"): # XXX: Why do we enable memcbs for memory writes?
            self.enable_memcb()
        buf = ffi.new("char[]", length)

        buf_a = ffi.cast("char*", buf)
        length_a = ffi.cast("int", length)
        if physical:
            err = self.libpanda.panda_physical_memory_read_external(addr, buf_a, length_a)
        else:
            err = self.libpanda.panda_virtual_memory_read_external(env, addr, buf_a, length_a)

        if err < 0:
            raise ValueError(f"Memory access failed with err={err}") # TODO: make a PANDA Exn class

        r = ffi.unpack(buf, length)
        if fmt == 'bytearray':
            return r
        elif fmt=='int':
            return int.from_bytes(r, byteorder=self.endianness)  # XXX size better be small enough to pack into an int!
        elif fmt=='str':
            return ffi.string(buf, length)
        else:
            raise ValueError("fmt={} unsupported".format(fmt))

    def physical_memory_write(self, addr, buf):
        return self._memory_write(None, addr, buf, physical=True)

    def virtual_memory_write(self, env, addr, buf):
        return self._memory_write(env, addr, buf, physical=False)

    def _memory_write(self, env, addr, buf, physical=False):
        '''
        Write a bytearray into memory at the specified physical/virtual address
        '''
        length = len(buf)
        c_buf = ffi.new("char[]",buf)
        buf_a = ffi.cast("char*", c_buf)
        length_a = ffi.cast("int", length)

        if not hasattr(self, "_memcb"): # XXX: Why do we enable memcbs for memory writes?
            self.enable_memcb()

        if physical:
            return self.libpanda.panda_physical_memory_write_external(addr, buf_a, length_a)
        else:
            return self.libpanda.panda_virtual_memory_write_external(env, addr, buf_a, length_a)

    def callstack_callers(self, lim, cpu): # XXX move into new directory, 'callstack' ?
        if not "plugin_callstack_instr" in self.plugins:
            progress("enabling callstack_instr plugin")
            self.require("callstack_instr")

        callers = ffi.new("uint32_t[%d]" % lim)
        n = self.plugins['callstack_instr'].get_callers(callers, lim, cpu)
        c = []
        for pc in callers:
            c.append(pc)
        return c

    def load_plugin_library(self, name):
        if hasattr(self,"__did_load_libpanda"):
            libpanda_path_chr = ffi.new("char[]",bytes(self.libpanda_path, "UTF-8"))
            self.__did_load_libpanda = self.libpanda.panda_load_libpanda(libpanda_path_chr)
        if not name in self.plugins.keys():
            assert(isfile(pjoin(*[self.build_dir, self.arch+"-softmmu", "panda/plugins/panda_{}.so".format(name)])))
            library = ffi.dlopen(pjoin(*[self.build_dir, self.arch+"-softmmu", "panda/plugins/panda_{}.so".format(name)]))
            self.plugins[name] = library

    def queue_async(self, f, internal=False):
        self.athread.queue(f, internal=internal)

    def map_memory(self, name, size, address):
        name_c = ffi.new("char[]", bytes(name, "utf-8"))
        size = ceil(size/1024)*1024 # Must be page-aligned
        return self.libpanda.map_memory(name_c, size, address)

    def read_str(self, cpu, ptr):
        '''
        Helper to read a null-terminated string from guest memory given a pointer and CPU state
        May return an exception if the call to panda.virtual_memory_read fails (e.g., if you pass a
        pointer to an unmapped page)
        '''
        r = b""
        while True:
            next_char = self.virtual_memory_read(cpu, ptr, 1) # If this raises an exn, don't mask it
            if next_char == b"\x00":
                break
            r += next_char
            ptr += 1
        return r.decode("utf8", "ignore")

    def to_unsigned_guest(self, x):
        '''
        Convert a singed python int to an unsigned int32/unsigned int64
        depending on guest bit-size
        '''
        import ctypes
        if self.bits == 32:
            return ctypes.c_uint32(x).value
        elif self.bits == 64:
            return ctypes.c_uint64(x).value
        else:
            raise ValueError("Unsupported number of bits")

    def from_unsigned_guest(self, x):
        '''
        Convert an unsigned int32/unsigned int64 from the guest
        (depending on guest bit-size) to a (signed) python int
        '''
        if x >= 2**(self.bits-1): # If highest bit is set, it's negative
            return (x - 2**self.bits)
        else: # Else it's positive
            return x

# vim: expandtab:tabstop=4:
