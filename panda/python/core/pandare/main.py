"""
The main module is a container for the Panda class.
"""

import sys

if sys.version_info[0] < 3:
    print("Please run with Python 3!")
    sys.exit(0)

import socket
import threading

from os.path import realpath, exists, abspath, isfile, dirname, join as pjoin
from os import dup, getenv, environ, path
from random import randint
from inspect import signature
from tempfile import NamedTemporaryFile
from time import time
from math import ceil
from inspect import signature
from struct import pack_into
from shlex import quote as shlex_quote
from time import sleep
from cffi import FFI

from .ffi_importer import ffi
from .utils import progress, make_iso, debug, blocking, GArrayIterator, plugin_list
from .taint import TaintQuery
from .panda_expect import Expect
from .asyncthread import AsyncThread
from .qcows import Qcows
from .arch import ArmArch, MipsArch, X86Arch, X86_64Arch

# Might be worth importing and auto-initilizing a PLogReader
# object within Panda for the current architecture?
#from .plog import PLogReader


class Panda():
    '''
    This is the object used to interact with PANDA. Initializing it creates a virtual machine to interact with.

        Parameters:
            arch : architecture string (e.g. "i386", "x86_64", "arm", "mips", "mipsel")
            mem : size of memory for machine (e.g. "128M", "1G")
            expect_prompt : Regular expression describing the prompt exposed by the guest 
                on a serial console. Used so we know when a running command has finished 
                with its output.
            os_version : analagous to -os string.
            qcow : qcow file to load as a path
            os : type of OS (e.g. "linux")
            generic : specify a generic qcow to use and set other arguments. Supported 
                values: arm/ppc/x86_64/i386. Will download qcow automatically
            raw_monitor : When set, don't specify a -monitor. arg Allows for use of 
                -nographic in args with ctrl-A+C for interactive qemu prompt.
            extra_args : extra arguments to pass to PANDA as either a string or an 
                array. (e.g. "-nographic" or ["-nographic", "-net", "none"])

    Note that multiple PANDA objects cannot coexist in the same Python instance.
    '''
    def __init__(self, arch="i386", mem="128M",
            expect_prompt=None, # Regular expression describing the prompt exposed by the guest on a serial console. Used so we know when a running command has finished with its output
            os_version=None,
            qcow=None, # Qcow file to load
            os="linux",
            generic=None, # Helper: specify a generic qcow to use and set other arguments. Supported values: arm/ppc/x86_64/i386. Will download qcow automatically
            raw_monitor = False, # When set, don't specify a -monitor. arg Allows for use of -nographic in args with ctrl-A+C for interactive qemu prompt.
            extra_args=[]):
        self.arch_name = arch
        self.mem = mem
        self.os = os_version
        self.os_type = os
        self.qcow = qcow
        self.plugins = plugin_list(self)
        self.expect_prompt = expect_prompt
        self.lambda_cnt = 0

        if isinstance(extra_args, str): # Extra args can be a string or array
            extra_args = extra_args.split()

        # If specified use a generic (x86_64, i386, arm, ppc) qcow from mit and ignore
        if generic:                                 # other args. See details in images.py
            print("using generic " +str(generic))
            q = Qcows.get_qcow_info(generic)
            self.arch_name     = q.arch
            self.os       = q.os
            self.mem      = q.default_mem # Might clobber a specified argument, but required if you want snapshots
            self.qcow     = Qcows.get_qcow(generic)
            self.expect_prompt = q.prompt
            if q.extra_args:
                extra_args.extend(q.extra_args.split(" "))

        if self.qcow: # Otherwise we shuld be able to do a replay with no qcow but this is probably broken
            if not (exists(self.qcow)):
                print("Missing qcow '{}' Please go create that qcow and give it to the PANDA maintainers".format(self.qcow))

        # panda.arch is a subclass with architecture-specific functions

        if self.arch_name == "i386":
            self.arch = X86Arch(self)
        elif self.arch_name == "x86_64":
            self.arch = X86_64Arch(self)
        elif self.arch_name == "arm":
            self.arch = ArmArch(self)
        elif self.arch_name in ["mips", "mipsel"]:
            self.arch = MipsArch(self)
        else:
            raise ValueError(f"Unsupported architecture {self.arch_name}")
        self.bits, self.endianness, self.register_size = self.arch._determine_bits()

        self.build_dir  = self._find_build_dir()
        environ["PANDA_DIR"] = self.build_dir
        self.libpanda_path = pjoin(self.build_dir, "{0}-softmmu/libpanda-{0}.so".format(self.arch_name))
        self.panda = self.libpanda_path # Necessary for realpath to work inside core-panda, may cause issues?

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
        self.panda_args.extend(['-m', self.mem])

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
        self._registered_mmap_cb = False

        self._initialized_panda = False
        self.disabled_tb_chaining = False
        self.taint_enabled = False
        self.hook_list = {}

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
        environ["PANDA_ARCH"] = self.arch_name
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
        path_end = "{0}-softmmu/libpanda-{0}.so".format(self.arch_name)

        pot_paths = [python_package, local_build]
        for potential_path in pot_paths:
            if isfile(pjoin(potential_path, path_end)):
                print("Loading libpanda from {}".format(potential_path))
                return potential_path

        searched_paths = "\n".join(["\t"+p for p in  pot_paths])
        raise RuntimeError(("Couldn't find libpanda-{}.so.\n"
                            "Did you built PANDA for this architecture?\n"
                            "Searched paths:\n{}"
                           ).format(self.arch_name, searched_paths))


    def queue_main_loop_wait_fn(self, fn, args=[]):
        '''
        Queue a function to run at the next main loop
        fn is a function we want to run, args are arguments to apss to it
        '''
        self.main_loop_wait_fnargs.append((fn, args))

    def exit_cpu_loop(self):
        '''
        Stop cpu execution at nearest juncture.
        '''
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

    def reset(self): 
        """In the next main loop, reset to boot"""
        if debug:
            progress ("Resetting machine to start state")

        # Stop guest, queue up revert, then continue
        self.vm_stop()
        self.queue_main_loop_wait_fn(self.libpanda.panda_reset)
        self.queue_main_loop_wait_fn(self.libpanda.panda_cont)

    def cont(self):
        ''' Continue execution (run after vm_stop) '''
        self.libpanda.panda_cont()
        self.running.set()

    def vm_stop(self, code=4):
        ''' Stop execution, default code means RUN_STATE_PAUSED '''
        self.libpanda.panda_stop(code)

    def snap(self, snapshot_name):
        ''' Create snapshot with specified name '''
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
        ''' Delete snapshot with specified name '''
        if debug:
            progress ("Deleting snapshot " + snapshot_name)

        # Stop guest, queue up delete, then continue
        self.vm_stop()
        charptr = ffi.new("char[]", bytes(snapshot_name, "utf-8"))
        self.queue_main_loop_wait_fn(self.libpanda.panda_delvm, [charptr])

    def finish_timer(self, start, msg):
        ''' Print how long some (main_loop_wait) task took '''
        t = time() - start
        print("{} in {1:.08f} seconds".format(msg, t))


    def enable_tb_chaining(self):
        ''' This function enables translation block chaining in QEMU '''
        if debug:
            progress("Enabling TB chaining")
        self.disabled_tb_chaining = False
        self.libpanda.panda_enable_tb_chaining()

    def disable_tb_chaining(self):
        ''' This function disables translation block chaining in QEMU '''
        if not self.disabled_tb_chaining:
            if debug:
                progress("Disabling TB chaining")
            self.disabled_tb_chaining = True
            self.libpanda.panda_disable_tb_chaining()

    def run(self):
        '''
        This function starts our running PANDA instance from Python. At termination this function returns and the script continues to run after it.
        
        This function starts execution of the guest. It blocks until guest finishes.
        It also initializes panda object, clears main_loop_wait fns, and sets up internal callbacks.
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
        Stop running machine.

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
        Load a replay and run it. Starts PANDA execution and returns after end of VM execution.

            Parameters:
                replaypfx: python string path to replay file.
        
            Returns:
                None
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

            Parameters:
                name: python string name of plugin
                args: Dictionary of arguments matching key to value. e.g. {"key": "value"} sets option key to value.
            
            Returns:
                None.
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
        self._load_plugin_library(name)

    def unload_plugin(self, name):
        '''
        Unload plugin with given name.

            Parameters:
                name: python string name of plugin
        
            Returns:
                None
        '''
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

    def memsavep(self, file_out):
        '''
        Calls QEMU memsavep on your specified python file.
        '''
        newfd = dup(file_out.fileno())
        self.libpanda.panda_memsavep(newfd)
        self.libpanda.fclose(newfd)

    def physical_memory_read(self, addr, length, fmt='bytearray'):
        '''
        Read guest physical memory.

            Parameters:
                addr: python int address
                length: length of array you would like returned
                fmt: format for returned array. Options: 'bytearray', 'int', and 'str'

            Returns:
                Buffer based on fmt string
        
            Raises:
                ValueError for two cases: 
                    Memory Access with error value.
                    Format string is incorrect.
        '''
        return self._memory_read(None, addr, length, physical=True, fmt=fmt)

    def virtual_memory_read(self, env, addr, length, fmt='bytearray'):
        '''
        Read guest virtual memory.

            Parameters:
                    env: CPUState structure
                    addr: python int address
                    length: length of array you would like returned
                    fmt: format for returned array. Options: 'bytearray', 'int', and 'str'
            
            Returns:
                    Buffer based on fmt string
            
            Raises:
                    ValueError for two cases: 
                        Memory Access with error value.
                        Format string is incorrect.
        '''
        return self._memory_read(env, addr, length, physical=False, fmt=fmt)

    def _memory_read(self, env, addr, length, physical=False, fmt='bytearray'):
        '''
        Read but with an autogen'd buffer
        Supports physical or virtual addresses
        Raises ValueError if read fails
        '''
        if not hasattr(self, "_memcb"): # XXX: Why do we enable memcbs for memory writes?
            self.enable_memcb()
        buf = ffi.new("char[]", length)

        # Force CFFI to parse addr as an unsigned value. Otherwise we get OverflowErrors
        # when it decides that it's negative
        ptr_typ = f'uint{self.bits}_t'
        addr_u = int(ffi.cast(ptr_typ, addr))

        buf_a = ffi.cast("char*", buf)
        length_a = ffi.cast("int", length)
        if physical:
            err = self.libpanda.panda_physical_memory_read_external(addr_u, buf_a, length_a)
        else:
            err = self.libpanda.panda_virtual_memory_read_external(env, addr_u, buf_a, length_a)

        if err < 0:
            raise ValueError(f"Memory access failed with err={err}") # TODO: make a PANDA Exn class

        r = ffi.unpack(buf, length)
        if fmt == 'bytearray':
            return r
        elif fmt=='int':
            return int.from_bytes(r, byteorder=self.endianness)  # XXX size better be small enough to pack into an int!
        elif fmt=='str':
            return ffi.string(buf, length)
        elif fmt=='ptrlist':
            # This one is weird. Chunmk the memory into byte-sequences of (self.bits/8) bytes and flip endianness as approperiate
            # return a list
            bytelen = int(self.bits/8)
            if (length % bytelen != 0):
                raise ValueError(f"Memory of size {length} does not evenly divide into {bytelen} byte chunks")
            chunks = []
            for start in range(0, length, bytelen):
                data = r[start:start+bytelen]
                int_data = int.from_bytes(data, byteorder=self.endianness)
                chunks.append(int_data)
            return chunks

        else:
            raise ValueError("fmt={} unsupported".format(fmt))

    def physical_memory_write(self, addr, buf):
        '''
        Write guest physical memory.

            Parameters:
                    addr: python int address
                    buf:  byte string to write
        '''
        return self._memory_write(None, addr, buf, physical=True)

    def virtual_memory_write(self, env, addr, buf):
        '''
        Write guest virtual memory.
        
            Parameters:
                    env: CPUState structure
                    address: python int address
                    buf: byte string to write
            
            Returns:
                    int: 0 on success. 1 on error.

        '''
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
        '''
        Utility function to handle conversion and return get_callers from callstack_instr.
        '''
        if not "plugin_callstack_instr" in self.plugins:
            progress("enabling callstack_instr plugin")
            self.require("callstack_instr")

        callers = ffi.new("uint32_t[%d]" % lim)
        n = self.plugins['callstack_instr'].get_callers(callers, lim, cpu)
        c = []
        for pc in callers:
            c.append(pc)
        return c

    def _load_plugin_library(self, name):
        if hasattr(self,"__did_load_libpanda"):
            libpanda_path_chr = ffi.new("char[]",bytes(self.libpanda_path, "UTF-8"))
            self.__did_load_libpanda = self.libpanda.panda_load_libpanda(libpanda_path_chr)
        if not name in self.plugins.keys():
            assert(isfile(pjoin(*[self.build_dir, self.arch_name+"-softmmu", "panda/plugins/panda_{}.so".format(name)])))
            library = ffi.dlopen(pjoin(*[self.build_dir, self.arch_name+"-softmmu", "panda/plugins/panda_{}.so".format(name)]))
            self.plugins[name] = library

    def queue_async(self, f, internal=False):
        '''
        Queues work in the asynchronous work queue.

            Parameters:
                f: A python function with no arguments to be called at a later date
            
            Returns:
                None
        '''
        self.athread.queue(f, internal=internal)

    def map_memory(self, name, size, address):

        '''
        Make a new memory region.
        
            Parameters:
                    name: This is an internal reference name for this region. Must be unique.
                    size: number of bytes the region should be.
                    address: start address of region
        '''

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

    ########################## LIBPANDA FUNCTIONS ########################
    # Methods that directly pass data to/from PANDA with no extra logic beyond argument reformatting.
    def set_pandalog(self, name):
        '''
        Start up pandalog with specified file

            Parameters:
                name: file to output data to
            
            Returns:
                None
        '''
        charptr = ffi.new("char[]", bytes(name, "utf-8"))
        self.libpanda.panda_start_pandalog(charptr)

    def enable_memcb(self):
        '''
        Enable memory callbacks. Must be called for memory callbacks to work.
        pypanda enables this automatically with some callbacks.
        '''
        self._memcb = True
        self.libpanda.panda_enable_memcb()
    
    def disable_memcb(self):
        '''
        Disable memory callbacks. Must be enabled for memory callbacks to work.
        pypanda enables this automatically with some callbacks.
        '''
        self._memcb = False
        self.libpanda.panda_disable_memcb()

    def virt_to_phys(self, env, addr):
        '''
        Convert virtual address to physical address.

            Parameters:
                env: CPUState struct
                addr (int): virtual address to convert
            
            Return:
                physical address as python int
        '''
        return self.libpanda.panda_virt_to_phys_external(env, addr)

    def enable_plugin(self, handle):
        '''
        Enable plugin.

            Parameters:
                handle: pointer to handle returned by plugin
            
            Return:
                None
        '''
        self.libpanda.panda_enable_plugin(handle)

    def disable_plugin(self, handle):
        '''
        Disable plugin.

            Parameters:
                handle: pointer to handle returned by plugin
            
            Return:
                None
        '''
        self.libpanda.panda_disable_plugin(handle)

    def enable_llvm(self):
        '''
        Enables the use of the LLVM JIT in replacement of the TCG (QEMU intermediate language and compiler) backend. 
        '''
        self.libpanda.panda_enable_llvm()

    def disable_llvm(self):
        '''
        Disables the use of the LLVM JIT in replacement of the TCG (QEMU intermediate language and compiler) backend. 
        '''
        self.libpanda.panda_disable_llvm()

    def enable_llvm_helpers(self):
        '''
        Enables the use of Helpers for the LLVM JIT in replacement of the TCG (QEMU intermediate language and compiler) backend. 
        '''
        self.libpanda.panda_enable_llvm_helpers()

    def disable_llvm_helpers(self):
        '''
        Disables the use of Helpers for the LLVM JIT in replacement of the TCG (QEMU intermediate language and compiler) backend. 
        '''
        self.libpanda.panda_disable_llvm_helpers()

    def flush_tb(self):
        '''
        This function requests that the translation block cache be flushed as soon as possible. If running with translation block chaining turned off (e.g. when in LLVM mode or replay mode), this will happen when the current translation block is done executing.
        Flushing the translation block cache is additionally necessary if the plugin makes changes to the way code is translated. For example, by using panda_enable_precise_pc.
        '''
        return self.libpanda.panda_flush_tb()

    def enable_precise_pc(self):
        '''
        By default, QEMU does not update the program counter after every instruction.
        This function enables precise tracking of the program counter. After enabling precise PC tracking, the program counter will be available in env->panda_guest_pc and can be assumed to accurately reflect the guest state.
        '''
        self.libpanda.panda_enable_precise_pc()

    def disable_precise_pc(self):
        '''
        By default, QEMU does not update the program counter after every instruction.
        This function disables precise tracking of the program counter.
        '''
        self.libpanda.panda_disable_precise_pc()

    def in_kernel(self, cpustate):
        '''
        Returns true if the processor is in the privilege level corresponding to executing kernel code for any of the PANDA supported architectures.
        '''
        return self.libpanda.panda_in_kernel_external(cpustate)

    def g_malloc0(self, size):
        '''
        Helper function to call glib malloc

            Parameters:
                size: size to call with malloc
            
            Returns:
                buffer of that size from malloc
        '''
        return self.libpanda.g_malloc0(size)

    def current_sp(self, cpustate):
        '''
        Get current stack pointer

            Parameters:
                cpustate: CPUState struct

            Return:
                integer value of stack pointer
        '''
        return self.libpanda.panda_current_sp_external(cpustate)

    def current_pc(self, cpustate):
        '''
        Get current program counter

            Parameters:
                cpustate: CPUState struct

            Return:
                integer value of current program counter

            .. Deprecated:: Use panda.arch.get_pc(cpu) instead
        '''
        return self.libpanda.panda_current_pc(cpustate)


    def current_asid(self, cpustate):
        '''
        Get current Application Specific ID
            
            Parameters:
                cpustate: CPUState struct

            Return:
                integer value of current ASID
        '''
        return self.libpanda.panda_current_asid(cpustate)

    def disas2(self, code, size):
        '''
        Call panda_disas to diasassemble an amount of code at a pointer.
        FIXME: seem to not match up to PANDA definition
        '''
        self.libpanda.panda_disas(code, size)

    def cleanup(self):
        '''
        Unload all plugins and close pandalog.
        '''
        self.libpanda.panda_cleanup()

    def was_aborted(self):
        '''
        Returns true if panda was aborted.
        '''
        return self.libpanda.panda_was_aborted()

    def get_cpu(self):
        '''
        This function returns first_cpu CPUState object from QEMU.
        XXX: You rarely want this
        '''
        return self.libpanda.get_cpu()

    def garray_len(self, garray):
        '''
        Convenience function to get array length of glibc array.
        '''
        return self.libpanda.garray_len(garray)

    def panda_finish(self):
        '''
        Final stage call to underlying panda_finish with initialization.
        '''
        return self.libpanda.panda_finish()

    def rr_get_guest_instr_count(self):
        '''
        Returns record/replay guest instruction count.
        '''
        return self.libpanda.rr_get_guest_instr_count_external()

    ################### LIBQEMU Functions ############
    #Methods that directly pass data to/from QEMU with no extra logic beyond argument reformatting.
    #All QEMU function can be directly accessed by Python. These are here for convenience.
    # It's usally better to find a function name and look at the QEMU source for these functions.

    def drive_get(self, blocktype, bus, unit):
        '''
        Gets DriveInfo struct from user specified information.

            Parameters:
                blocktype: BlockInterfaceType structure
                bus: integer bus
                unit: integer unit
            
            Return:
                DriveInfo struct
        '''
        return self.libpanda.drive_get(blocktype,bus,unit)

    def sysbus_create_varargs(self, name, addr):
        '''
        Returns DeviceState struct from user specified information
        Calls sysbus_create_varargs QEMU function.

            Parameters:
                name: python string
                addr: python integer representing hwaddr
            
            Return:
                DeviceState struct
        '''
        return self.libpanda.sysbus_create_varargs(name,addr,ffi.NULL)

    def cpu_class_by_name(self, name, cpu_model):
        '''
        Gets cpu class from name.
        Calls cpu_class_by_name QEMU function.

            Parameters:
                name: typename from python string
                cpu_model: string specified cpu model

            Returns:
                ObjectClass struct
        '''
        return self.libpanda.cpu_class_by_name(name, cpu_model)

    def object_class_by_name(self, name):
        '''
        Returns class as ObjectClass from name specified.
        Calls object_class_by_name QEMU function.

            Parameters:
                name: string defined by user
            
            Returns:
                struct as specified by name
        '''
        return self.libpanda.object_class_by_name(name)

    def object_property_set_bool(self, obj, value, name):
        '''
        Writes a bool value to a property.
        Calls object_property_set_bool QEMU function.

            Parameters:
                value: the value to be written to the property
                name: the name of the property
                errp: returns an error if this function fails

            Returns:
                None
        '''
        return self.libpanda.object_property_set_bool(obj,value,name,self.libpanda.error_abort)

    def object_class_get_name(self, objclass):
        '''
        Gets String QOM typename from object class.
        Calls object_class_get_name QEMU function.

            Parameters:
                objclass: class to obtain the QOM typename for.

            Returns: 
                String QOM typename for klass.
        '''
        return self.libpanda.object_class_get_name(objclass)

    def object_new(self, name):
        '''
        Creates a new object from typename.
        This function will initialize a new object using heap allocated memory.
        The returned object has a reference count of 1, and will be freed when
        the last reference is dropped.
        Calls object_new QEMU function.
            
            Parameters:
                name: The name of the type of the object to instantiate.
            
            Returns: 
                The newly allocated and instantiated object.
        '''
        return self.libpanda.object_new(name)

    def object_property_get_bool(self, obj, name):
        '''
        Pull boolean from object.
        Calls object_property_get_bool QEMU function.

            Parameters:
                obj: the object
                name: the name of the property
            
            Returns: 
                the value of the property, converted to a boolean, or NULL if an error occurs (including when the property value is not a bool).
        '''
        return self.libpanda.object_property_get_bool(obj,name,self.libpanda.error_abort)

    def object_property_set_int(self,obj, value, name):
        '''
        Set integer in QEMU object. Writes an integer value to a property.   
        Calls object_property_set_int QEMU function.
        
            Parameters:
                value: the value to be written to the property
                name: the name of the property
            
            Returns:
                None
        '''
        return self.libpanda.object_property_set_int(obj, value, name, self.libpanda.error_abort)

    def object_property_get_int(self, obj, name):
        '''
        Gets integer in QEMU object. Reads an integer value from this property.   
        Calls object_property_get_int QEMU function.

            Paramaters:
                obj: the object
                name: the name of the property
            
            Returns: 
                the value of the property, converted to an integer, or negative if an error occurs (including when the property value is not an integer).
        '''
        return self.libpanda.object_property_get_int(obj, name, self.libpanda.error_abort)

    def object_property_set_link(self, obj, val, name):
        '''
        Writes an object's canonical path to a property.
        Calls object_property_set_link QEMU function.

            Parameters:
                value: the value to be written to the property
                name: the name of the property
                errp: returns an error if this function fails

            Returns:
                None
        '''
        return self.libpanda.object_property_set_link(obj,val,name,self.libpanda.error_abort)

    def object_property_get_link(self, obj, name):
        '''
        Reads an object's canonical path to a property.
        Calls object_property_get_link QEMU function.
    
            Parameters:
                obj: the object
                name: the name of the property
                errp: returns an error if this function fails
            
            Returns:
                the value of the property, resolved from a path to an Object, or NULL if an error occurs (including when the property value is not a string or not a valid object path).
        '''
        return self.libpanda.object_property_get_link(obj,name,self.libpanda.error_abort)

    def object_property_find(self, obj, name):
        '''
        Look up a property for an object and return its #ObjectProperty if found.
        Calls object_property_find QEMU function.

            Parameters:
                obj: the object
                name: the name of the property
                errp: returns an error if this function fails
            
            Returns:
                struct ObjectProperty pointer
        '''
        return self.libpanda.object_property_find(obj,name,ffi.NULL)

    def memory_region_allocate_system_memory(self, mr, obj, name, ram_size):
        '''
        Allocates Memory region by user specificiation.
        Calls memory_region_allocation_system_memory QEMU function.

            Parameters:
                mr: MemoryRegion struct
                obj: Object struct
                name: string of region name
                ram_size: int of ram size
            
            Returns:
                None
        '''
        return self.libpanda.memory_region_allocate_system_memory(mr, obj, name, ram_size)

    def memory_region_add_subregion(self, mr, offset, sr):
        '''
        Calls memory_region_add_subregion from QEMU.
        memory_region_add_subregion: Add a subregion to a container.
        
        Adds a subregion at @offset.  The subregion may not overlap with other
        subregions (except for those explicitly marked as overlapping).  A region
        may only be added once as a subregion (unless removed with
        memory_region_del_subregion()); use memory_region_init_alias() if you
        want a region to be a subregion in multiple locations.
        
            Parameters:
                mr: the region to contain the new subregion; must be a container initialized with memory_region_init().
                offset: the offset relative to @mr where @subregion is added.
                subregion: the subregion to be added.
            
            Returns: 
                None
        '''
        return self.libpanda.memory_region_add_subregion(mr,offset,sr)

    def memory_region_init_ram_from_file(self, mr, owner, name, size, share, path):
        '''
        Calls memory_region_init_ram_from_file from QEMU.
        memory_region_init_ram_from_file:  Initialize RAM memory region with a mmap-ed backend.
        
            Parameters:
                mr: the #MemoryRegion to be initialized.
                owner: the object that tracks the region's reference count
                name: the name of the region.
                size: size of the region.
                share: %true if memory must be mmaped with the MAP_SHARED flag
                path: the path in which to allocate the RAM.
                errp: pointer to Error*, to store an error if it happens.
            
            Returns:
                None
        '''
        return self.libpanda.memory_region_init_ram_from_file(mr, owner, name, size, share, path, self.libpanda.error_fatal)

    def create_internal_gic(self, vbi, irqs, gic_vers):
        return self.libpanda.create_internal_gic(vbi, irqs, gic_vers)

    def create_one_flash(self, name, flashbase, flashsize, filename, mr):
        return self.libpanda.create_one_flash(name, flashbase, flashsize, filename, mr)

    def create_external_gic(self, vbi, irqs, gic_vers, secure):
        return self.libpanda.create_external_gic(vbi, irqs, gic_vers, secure)

    def create_virtio_devices(self, vbi, pic):
        return self.libpanda.create_virtio_devices(vbi, pic)

    def arm_load_kernel(self, cpu, bootinfo):
        return self.libpanda.arm_load_kernel(cpu, bootinfo)

    def error_report(self, s):
        return self.libpanda.error_report(s)

    def get_system_memory(self):
        return self.libpanda.get_system_memory()

    def lookup_gic(self,n):
        return self.libpanda.lookup_gic(n)

    ##################### OSI FUNCTIONS ###########
    #Convenience functions to interact with the Operating System Instrospection (OSI) class of plugins.

    def set_os_name(self, os_name):
        """
        Set OS target. Equivalent to "-os" flag on the command line. Matches the form of:
        
            "windows[-_]32[-_]xpsp[23]",
            "windows[-_]32[-_]7",
            "windows[-_]32[-_]2000",
            "linux[-_]32[-_].+",
            "linux[-_]64[-_].+",

            Parameters:
                os_name: string matching the format for the os flag.
            
            Returns:
                None
        """
        os_name_new = ffi.new("char[]", bytes(os_name, "utf-8"))
        self.libpanda.panda_set_os_name(os_name_new)


    def get_mappings(self, cpu):
        '''
        Get all active memory mappings in the system.

            Requires: OSI

            Parameters:
                cpu: CPUState struct

            Returns:
                Iterator of `OsiModule` structures
        '''
        current = self.plugins['osi'].get_current_process(cpu)
        maps = self.plugins['osi'].get_mappings(cpu, current)
        map_len = self.garray_len(maps)
        return GArrayIterator(self.plugins['osi'].get_one_module, maps, map_len, self.plugins['osi'].cleanup_garray)

    def get_processes(self, cpu):
        '''
        Get all running processes in the system. Includes kernel modules on Linux.

            Requires: OSI

            Parameters:
                cpu: CPUState struct

            Returns:
                Iterator of `OsiProc` structures
        '''
        processes = self.plugins['osi'].get_processes(cpu)
        processes_len = self.garray_len(processes)
        return GArrayIterator(self.plugins['osi'].get_one_proc, processes, processes_len, self.plugins['osi'].cleanup_garray)

    def get_processes_dict(self, cpu):
        '''
        Get all running processes for the system at this moment in time as a dictionary.

        The dictionary maps proceses by their PID. Each mapping returns a dictionary containing the process name, its pid,
        and its parent pid (ppid).

            Requires: OSI

            Parameters:
                cpu: CPUState struct

            Returns:
                Dictionary as described above.
        '''

        procs = {} #pid: {name: X, pid: Y, parent_pid: Z})

        for proc in self.get_processes(cpu):
            assert(proc != ffi.NULL)
            assert(proc.pid not in procs)
            procs[proc.pid] = {"name": ffi.string(proc.name).decode('utf8', 'ignore'), 'pid': proc.pid, 'parent_pid': proc.ppid}
            assert(not (proc.pid != 0 and proc.pid == proc.ppid)) # No cycles allowed other than at 0
        return procs

    def get_process_name(self, cpu):
        '''
        Get the name of the current process. May return None if OSI cannot identify the current process
        '''
        proc = self.plugins['osi'].get_current_process(cpu)
        if proc == ffi.NULL or proc.name == ffi.NULL:
            return None

        procname = ffi.string(proc.name).decode('utf8', 'ignore')
        return ffi.string(proc.name).decode('utf8', 'ignore')


    ################## PYPERIPHERAL FUNCTIONS #####################
    # Pyperipherals are objects which handle mmio read/writes using the PANDA callback infrastructure.
    # Under the hood, they use the cb_unassigned_io_read/cb_unassigned_io_write callbacks.
    # A python peripheral itself is an object which exposes the following functions:
    #     write_memory(self, address, size, value)
    #     read_memory(self, address, size)
    # And has at least the following attributes:
    #     address
    #     size

    # One example for such a python object are avatar2's AvatarPeripheral.
    def _addr_to_pyperipheral(self, address):
        """
        Returns the python peripheral for a given address, or None if no
        peripheral is registered for that address
        """

        for pp in self.pyperipherals:
            if pp.address <= address < pp.address + pp.size:
                return pp
        return None

    def _validate_object(self, object):
        # This function makes sure that the object exposes the right interfaces

        if not hasattr(object, "address") or not isinstance(object.address, int):
            raise RuntimeError(
                (
                    "Registering PyPeripheral %s failed:\n"
                    "Missing or non-int `address` attribute"
                ).format(object.__repr__())
            )

        if not hasattr(object, "size") or not isinstance(object.size, int):
            raise RuntimeError(
                (
                    "Registering PyPeripheral %s failed:\n"
                    "Missing or non-int `address` attribute"
                ).format(object.__repr__())
            )

        if not hasattr(object, "read_memory"):
            raise RuntimeError(
                (
                    "Registering PyPeripheral %s failed:\n"
                    "Missing read_memory function"
                ).format(object.__repr__())
            )

        params = list(signature(object.read_memory).parameters)
        if params[0] != "address" or params[1] != "size":
            raise RuntimeError(
                (
                    "Registering PyPeripheral %s failed:\n"
                    "Invalid function signature for read_memory"
                ).format(object.__repr__())
            )

        if not hasattr(object, "write_memory"):
            raise RuntimeError(
                (
                    "Registering PyPeripheral %s failed:\n"
                    "Missing write_memory function"
                ).format(object.__repr__())
            )

        params = list(signature(object.write_memory).parameters)
        if params[0] != "address" or params[1] != "size" or params[2] != "value":
            raise RuntimeError(
                (
                    "Registering PyPeripheral %s failed:\n"
                    "Invalid function signature for write_memory"
                ).format(object.__repr__())
            )

        # Ensure object is not overlapping with any other pyperipheral
        if (
            self._addr_to_pyperipheral(object.address) is not None
            or self._addr_to_pyperipheral(object.address + object.size) is not None
        ):
            raise RuntimeError(
                (
                    "Registering PyPeripheral %s failed:\n" "Overlapping memories!"
                ).format(object.__repr__())
            )

        return True

    def pyperiph_read_cb(self, cpu, pc, physaddr, size, val_ptr):
        pp = self._addr_to_pyperipheral(physaddr)
        if pp is None:
            return False

        val = pp.read_memory(physaddr, size)
        buf = ffi.buffer(val_ptr, size)

        fmt = "{}{}".format(self._end2fmt[self.endianness], self._num2fmt[size])

        pack_into(fmt, buf, 0, val)

        return True

    def pyperiph_write_cb(self, cpu, pc, physaddr, size, val):
        pp = self._addr_to_pyperipheral(physaddr)
        if pp is None:
            return False

        pp.write_memory(physaddr, size, val)
        return True

    def register_pyperipheral(self, object):
        """
        Registers a python peripheral, and the necessary attributes to the
        panda-object, if not present yet.
        """

        # if we are the first pyperipheral, register the pp-dict
        if not hasattr(self, "pyperipherals"):
            self.pyperipherals = []
            self.pyperipherals_registered_cb = False
            self._num2fmt = {1: "B", 2: "H", 4: "I", 8: "Q"}
            self._end2fmt = {"little": "<", "big": ">"}

        self._validate_object(object)

        if self.pyperipherals_registered_cb is False:
            self.register_callback(
                self.callback.unassigned_io_read,
                self.callback.unassigned_io_read(self.pyperiph_read_cb),
                "pyperipheral_read_callback",
            )

            self.register_callback(
                self.callback.unassigned_io_write,
                self.callback.unassigned_io_write(self.pyperiph_write_cb),
                "pyperipheral_write_callback",
            )

            self.pyperipherals_registered_cb = True

        self.pyperipherals.append(object)

    def unregister_pyperipheral(self, pyperiph):
        """
        deregisters a python peripheral.
        The pyperiph parameter can be either an object, or an address
        Returns true if the pyperipheral was successfully removed, else false.
        """

        if isinstance(pyperiph, int) is True:
            pp = self._addr_to_pyperipheral(pyperiph)
            if pp is None:
                return False
        else:
            if pyperiph not in self.pyperipherals:
                return False
            pp = pyperiph

        self.pyperipherals.remove(pp)

        # If we dont have any pyperipherals left, unregister callbacks
        if len(self.pyperipherals) == 0:
            self.disable_callback("pyperipheral_read_callback", forever=True)
            self.disable_callback("pyperipheral_write_callback", forever=True)
            self.pyperipherals_registered_cb = False
        return True

    ############## TAINT FUNCTIONS ###############
    # Convenience methods for interacting with the taint subsystem.
    def taint_enable(self, cont=True):
        """
        Inform python that taint is enabled.
        """
        if not self.taint_enabled:
            progress("taint not enabled -- enabling")
            self.vm_stop()
            self.require("taint2")
#            self.queue_main_loop_wait_fn(self.require, ["taint2"])
            self.queue_main_loop_wait_fn(self.plugins['taint2'].taint2_enable_taint, [])
            if cont:
                self.queue_main_loop_wait_fn(self.libpanda.panda_cont, [])
            self.taint_enabled = True

    # label all bytes in this register.
    # or at least four of them
    def taint_label_reg(self, reg_num, label):
        self.taint_enable(cont=False)
        #if debug:
        #    progress("taint_reg reg=%d label=%d" % (reg_num, label))

        # XXX must ensure labeling is done in a before_block_invalidate that rets 1
        #     or some other safe way where the main_loop_wait code will always be run
        #self.stop()
        for i in range(self.register_size):
            self.queue_main_loop_wait_fn(self.plugins['taint2'].taint2_label_reg, [reg_num, i, label])
        self.queue_main_loop_wait_fn(self.libpanda.panda_cont, [])

    def taint_label_ram(self, addr, label):
        self.taint_enable(cont=False)
        #if debug:
            #progress("taint_ram addr=0x%x label=%d" % (addr, label))

        # XXX must ensure labeling is done in a before_block_invalidate that rets 1
        #     or some other safe way where the main_loop_wait code will always be run
        #self.stop()
        self.queue_main_loop_wait_fn(self.plugins['taint2'].taint2_label_ram, [addr, label])
        self.queue_main_loop_wait_fn(self.libpanda.panda_cont, [])

    # returns true if any bytes in this register have any taint labels
    def taint_check_reg(self, reg_num):
        if not self.taint_enabled: return False
#        if debug:
#            progress("taint_check_reg %d" % (reg_num))
        for offset in range(self.register_size):
            if self.plugins['taint2'].taint2_query_reg(reg_num, offset) > 0:
                return True

    # returns true if this physical address is tainted
    def taint_check_ram(self, addr):
        if not self.taint_enabled: return False
        if self.plugins['taint2'].taint2_query_ram(addr) > 0:
            return True

    def taint_get_reg(self, reg_num):
        '''
        Returns array of results, one for each byte in this register
        None if no taint.  QueryResult struct otherwise
        '''
        if not self.taint_enabled: return None
        if debug:
            progress("taint_get_reg %d" % (reg_num)) 
        res = []
        for offset in range(self.register_size): 
            if self.plugins['taint2'].taint2_query_reg(reg_num, offset) > 0:
                query_res = ffi.new("QueryResult *")
                self.plugins['taint2'].taint2_query_reg_full(reg_num, offset, query_res)
                tq = TaintQuery(query_res, self.plugins['taint2'])
                res.append(tq)
            else:
                res.append(None)
        return res

    # returns array of results, one for each byte in this register
    # None if no taint.  QueryResult struct otherwise
    def taint_get_ram(self, addr):
        if not self.taint_enabled: return None
        if self.plugins['taint2'].taint2_query_ram(addr) > 0:
            query_res = ffi.new("QueryResult *")
            self.plugins['taint2'].taint2_query_ram_full(addr, query_res)
            tq = TaintQuery(query_res, self.plugins['taint2'])
            return tq
        else:
            return None

    # returns true if this laddr is tainted
    def taint_check_laddr(self, addr, off):
        if not self.taint_enabled: return False
        if self.plugins['taint2'].taint2_query_laddr(addr, off) > 0:
            return True

    # returns array of results, one for each byte in this laddr
    # None if no taint.  QueryResult struct otherwise
    def taint_get_laddr(self, addr, offset):
        if not self.taint_enabled: return None
        if self.plugins['taint2'].taint2_query_laddr(addr, offset) > 0:
            query_res = ffi.new("QueryResult *")
            self.plugins['taint2'].taint2_query_laddr_full(addr, offset, query_res)
            tq = TaintQuery(query_res, self.plugins['taint2'])
            return tq
        else:
            return None

    ############ Volatility mixins
    """
    Utilities to integrate Volatility with PANDA. Highly experimental.
    """

    def make_panda_file_handler(self, debug=False):
        '''
        Constructs a file and file handler that volatility can't ignore to back by PANDA physical memory
        '''
        from urllib.request import BaseHandler
        if 'PandaFileHandler' in globals():  # already initialized
            return
        panda = self

        class PandaFile(object):
            def __init__(self, length, panda):
                self.pos = 0
                self.length = length
                self.closed = False
                self.mode = "rb"
                self.name = "/tmp/panda.panda"
                self.panda = panda
                self.classname = type(self).__name__

            def readable(self):
                return self.closed

            def read(self, size=1):
                if self.panda.bits == 32 and self.panda.arch_name == "i386":
                    data = self.panda.physical_memory_read(
                        self.pos & 0xfffffff, size)
                else:
                    data = self.panda.physical_memory_read(self.pos, size)
                if debug:
                    print(self.classname+": Reading " +
                          str(size)+" bytes from "+hex(self.pos))
                self.pos += size
                return data

            def peek(self, size=1):
                return self.panda.physical_memory_read(self.pos, size)

            def seek(self, pos, whence=0):
                if whence == 0:
                    self.pos = pos
                elif whence == 1:
                    self.pos += pos
                else:
                    self.pos = self.length - pos
                if self.pos > self.length:
                    print(self.classname+": We've gone off the deep end")
                if debug:
                    print(self.classname+" Seeking to address "+hex(self.pos))

            def tell(self):
                return self.pos

            def close(self):
                self.closed = True

        class PandaFileHandler(BaseHandler):
            def default_open(self, req):
                if 'panda.panda' in req.full_url:
                    length = panda.libpanda.ram_size
                    if length > 0xc0000000:
                        length += 0x40000000  # 3GB hole
                    if debug:
                        print(type(self).__name__ +
                              ": initializing PandaFile with length="+hex(length))
                    return PandaFile(length=length, panda=panda)
                else:
                    return None

            def file_close(self):
                return True

        globals()["PandaFileHandler"] = PandaFileHandler

    def get_volatility_symbols(self, debug=False):
        try:
            from .volatility_cli_classes import CommandLineMoreEfficient
            from volatility.framework import contexts
            from volatility.framework.layers.linear import LinearlyMappedLayer
            from volatility.framework.automagic import linux
        except ImportError:
            print("Warning: Failed to import volatility")
            return None
        if "linux" in self.os_type:
            if not hasattr(self, "_vmlinux"):
                self.make_panda_file_handler(debug=debug)
                constructed_original = CommandLineMoreEfficient().run()
                linux.LinuxUtilities.aslr_mask_symbol_table(
                    constructed_original.context, constructed_original.config['vmlinux'], constructed_original.config['primary'])
                self._vmlinux = contexts.Module(
                    constructed_original.context, constructed_original.config['vmlinux'], constructed_original.config['primary'], 0)
            else:
                LinearlyMappedLayer.read.cache_clear()  # smearing technique
            return self._vmlinux
        else:
            print("Unsupported.")
            return None

    def run_volatility(self, plugin, debug=False):
        try:
            from .volatility_cli_classes import CommandLineRunFullCommand, StringTextRenderer
        except ImportError:
            print("Warning: Failed to import volatility")
            return None
        self.make_panda_file_handler(debug=debug)
        cmd = CommandLineRunFullCommand().run("-q -f panda.panda " + plugin)
        output = StringTextRenderer().render(cmd.run())
        return output

    ########## BLOCKING MIXINS ############
    '''
    Utilities to provide blocking interactions with PANDA. This includes serial and monitor interactions as well as file copy to the guest.
    XXX: Do not call any of the following from the main thread- they depend on the CPU loop running
    '''
    @blocking
    def stop_run(self):
        '''
        From a blocking thread, request vl.c loop to break. Returns control flow in main thread.
        In other words, once this is called, panda.run() will finish and your main thread will continue.
        If you also want to unload plugins, use end_analysis instead

        XXX: This doesn't work in replay mode
        '''
        self.libpanda.panda_break_vl_loop_req = True

    @blocking
    def run_serial_cmd(self, cmd, no_timeout=False, timeout=30):
        self.running.wait() # Can only run serial when guest is running
        self.serial_console.sendline(cmd.encode("utf8"))
        if no_timeout:
            result = self.serial_console.expect(timeout=9999)
        else:
            result = self.serial_console.expect(timeout=timeout)
        return result

    @blocking
    def run_serial_cmd_async(self, cmd, delay=1):
        '''
        Type a command and press enter in the guest. Return immediately. No results available
        Only use this if you know what you're doing!
        '''
        self.running.wait() # Can only run serial when guest is running
        self.serial_console.sendline(cmd.encode("utf8"))
        if delay:
            sleep(delay) # Ensure it has a chance to run

    @blocking
    def type_serial_cmd(self, cmd):
        #Can send message into socket without guest running (no self.running.wait())
        self.serial_console.send(cmd.encode("utf8")) # send, not sendline

    def finish_serial_cmd(self):
        result = self.serial_console.send_eol()
        result = self.serial_console.expect()
        return result

    @blocking
    def run_monitor_cmd(self, cmd):
        self.monitor_console.sendline(cmd.encode("utf8"))
        result = self.monitor_console.expect()
        return result

    @blocking
    def revert_sync(self, snapshot_name):
        result = self.run_monitor_cmd("loadvm {}".format(snapshot_name))
        if result.startswith("Length mismatch"):
            raise RuntimeError("QEMU machine's RAM size doesn't match snapshot RAM size!")
        return result

    @blocking
    def delvm_sync(self, snapshot_name):
        self.run_monitor_cmd("delvm {}".format(snapshot_name))

    @blocking
    def copy_to_guest(self, copy_directory, iso_name=None):
        if not iso_name: iso_name = copy_directory + '.iso'
        progress("Creating ISO {}...".format(iso_name))

        make_iso(copy_directory, iso_name)

        copy_directory = path.split(copy_directory)[-1] # Get dirname

        # 1) we insert the CD drive TODO: the cd-drive name should be a config option, see the values in qcow.py
        self.run_monitor_cmd("change ide1-cd0 \"{}\"".format(iso_name))

        # 2) run setup script
        # setup_sh: 
        #   Make sure cdrom didn't automount
        #   Make sure guest path mirrors host path
        #   if there is a setup.sh script in the directory,
        #   then run that setup.sh script first (good for scripts that need to
        #   prep guest environment before script runs)
        setup_sh = "mkdir -p {mount_dir}; while ! mount /dev/cdrom {mount_dir}; do sleep 0.3; " \
               " umount /dev/cdrom; done; {mount_dir}/setup.sh &> /dev/null || true " \
               .format(mount_dir = (shlex_quote(copy_directory)))
        progress("setup_sh = [%s] " % setup_sh)
        progress(self.run_serial_cmd(setup_sh))

    @blocking
    def record_cmd(self, guest_command, copy_directory=None, iso_name=None, setup_command=None, recording_name="recording", snap_name="root", ignore_errors=False):
        '''
        Take a recording as follows:
            0) Revert to the specified snapshot name if one is set. By default 'root'. Set to `None` if you have already set up the guest and are ready to record with no revert
            1) Create an ISO of files that need to be copied into the guest if copy_directory is specified. Copy them in
            2) Run the setup_command in the guest, if provided
            3) Type the command you wish to record but do not press enter to begin execution. This avoids the recording capturing the command being typed
            4) Begin the recording (name controlled by recording_name)
            5) Press enter in the guest to begin the command. Wait until it finishes.
            6) End the recording
        '''
        # 0) Revert to the specified snapshot
        if snap_name is not None:
            self.revert_sync(snap_name) # Can't use self.revert because that would would run async and we'd keep going before the revert happens

        # 1) Make copy_directory into an iso and copy it into the guest - It will end up at the exact same path
        if copy_directory: # If there's a directory, build an ISO and put it in the cddrive
            # Make iso
            self.copy_to_guest(copy_directory, iso_name)

        # 2) Run setup_command, if provided before we start the recording (good place to CD or install, etc)
        if setup_command:
            print(f"Running setup command {setup_command}")
            r = self.run_serial_cmd(setup_command)
            print(f"Setup command results: {r}")

        # 3) type commmand (note we type command, start recording, finish command)
        self.type_serial_cmd(guest_command)

        # 4) start recording
        self.run_monitor_cmd("begin_record {}".format(recording_name))

        # 5) finish command
        result = self.finish_serial_cmd()

        if debug:
            progress("Result of `{}`:".format(guest_command))
            print("\t"+"\n\t".join(result.split("\n"))+"\n")

        if "No such file or directory" in result and not ignore_errors:
            print("Bad output running command: {}".format(result))
            raise RuntimeError("Command not found while taking recording")

        if "cannot execute binary file" in result and not ignore_errors:
            print("Bad output running command: {}".format(result))
            raise RuntimeError("Could not execute binary while taking recording")

        # 6) End recording
        self.run_monitor_cmd("end_record")

        print("Finished recording")

    @blocking
    def check_crashed(self):
        '''
        After end_analysis, check if an exn was caught in a callback.
        If so, print traceback and kill this python instance
        TODO: currently prints 2 stack frames too low (shows pypanda internals), should hide those
        '''
        if self.exception is not None:
            import traceback, os
            try:
                raise self.exception
            except:
                traceback.print_exc()
            os._exit(1) # Force process to exit now

    @blocking
    def interact(self, confirm_quit=True):
        '''
        Expose console interactively until user types pandaquit
        Must be run in blocking thread.

        TODO: This should probably repace self.serial_console with something
        that directly renders output to the user. Then we don't have to handle
        buffering and other problems. But we will need to re-enable the serial_console
        interface after this returns
        '''
        print("PANDA: entering interactive mode. Type pandaquit to exit")
        prompt = self.expect_prompt.decode("utf8") if self.expect_prompt  else "$ "
        if not prompt.endswith(" "): prompt += " "
        while True:
            cmd = input(prompt) # TODO: Strip all control characters - Ctrl-L breaks things
            if cmd.strip() == 'pandaquit':
                if confirm_quit:
                    q = input("PANDA: Quitting interactive mode. Are you sure? (y/n) ")
                    if len(q) and q.lower()[0] == 'y':
                        break
                    else:
                        continue
                else: # No confirm - just break
                    break
            r = self.run_serial_cmd(cmd) # XXX: may timeout
            print(r)

    @blocking
    def do_panda_finish(self):
        '''
        Call panda_finish. Note this isn't really blocking - the
        guest should have exited by now, but queue this after
        (blocking) shutdown commands in our internal async queue
        so it must also be labeled as blocking.
        '''
#        assert (not self.running.is_set()), "Can't finish while still running"
        self.panda_finish()

    ################## CALLBACK FUNCTIONS ################
    # Mixin for handling callbacks and generation of decorators that allow users to register their own callbacks
    # such as panda.cb_before_block_exec()
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

        @self.ppp("syscalls2", "on_sys_brk_enter")
        def on_sys_brk_enter(cpu, pc, brk):
            name = self.get_process_name(cpu)
            asid = self.libpanda.panda_current_asid(cpu)
            if self.asid_mapping.get(asid, None) != name:
                self.asid_mapping[asid] = name
                self._procname_changed(cpu, name)

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
                self._procname_changed(cpu, name)
                self.disable_callback('__get_pending_procname_change') # Disabled to begin


        # Local function def
        @self.callback.asid_changed
        def __asid_changed(cpustate, old_asid, new_asid):
            '''
            When the ASID changes, check if we know its procname (in self.asid_mapping),
            if so, call panda._procname_changed(cpu, name). Otherwise, we enable __get_pending_procname_change CB, which
            waits until the procname changes. Then we grab the new procname, update self.asid_mapping and call
            panda._procname_changed(cpu, name)
            '''
            if old_asid == new_asid:
                return 0

            if new_asid not in self.asid_mapping: # We don't know this ASID->procname - turn on __get_pending_procname_change
                if not self.is_callback_enabled('__get_pending_procname_change'):
                    self.enable_callback('__get_pending_procname_change')
            else: # We do know this ASID->procname, just call procname_changed
                self._procname_changed(cpustate, self.asid_mapping[new_asid])

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
            if local_name == "<lambda>":
                local_name = f"<lambda_{self.lambda_cnt}>"
                self.lambda_cnt += 1
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
        ```
        @ppp("syscalls2", "on_sys_open_return")
        def my_fun(cpu, pc, filename, flags, mode):
            ...

        panda.disable_ppp("my_fun")
        ```

        -- OR --

        ```
        @ppp("syscalls2", "on_sys_open_return", name="custom")
        def my_fun(cpu, pc, filename, flags, mode):
            ...
        ```

        panda.disable_ppp("custom")
        '''

        (f, plugin_name, attr) = self.ppp_registered_cbs[name]
        self.plugins[plugin_name].__getattr__("ppp_remove_cb_"+attr)(f) # All PPP cbs start with this string
        del self.ppp_registered_cbs[name] # It's now safe to be garbage collected

    ########## GDB MIXINS ##############
    """
    Provides the ability to interact with a QEMU attached gdb session by setting and clearing breakpoints. Experimental.
    """

    def set_breakpoint(self, cpu, pc):
        '''
        Set a GDB breakpoint such that when the guest hits PC, execution is paused and an attached
        GDB instance can introspect on guest memory. Requires starting panda with -s, at least for now
        '''
        BP_GDB = 0x10
        self.libpanda.cpu_breakpoint_insert(cpu, pc, BP_GDB, ffi.NULL)

    def clear_breakpoint(self, cpu, pc):
        '''
        Remove a breakpoint
        '''
        BP_GDB = 0x10
        self.libpanda.cpu_breakpoint_remove(cpu, pc, BP_GDB)

    ############# HOOKING MIXINS ###############
    """
    Provides the ability to interact with the hooks2 plugin and receive callbacks based on user-provided criteria.
    """

    def enable_hook(self,hook_name):
        '''
        Set hook status to active.        
        '''
        if hook_name in self.hook_list:
            self.plugins['hooks2'].enable_hooks2(self.hook_list[hook_name])
        else:
            print("ERROR: Your hook name was not in the hook list")

    def disable_hook(self,hook_name):
        '''
        Set hook status to inactive.
        '''
        if hook_name in self.hook_list:
            self.plugins['hooks2'].disable_hooks2(self.hook_list[hook_name])
        else:
            print("ERROR: Your hook name was not in the hook list")

    def hook(self,name, kernel=True, procname=ffi.NULL, libname=ffi.NULL, trace_start=0, trace_stop=0, range_begin=0, range_end=0):
        if procname != ffi.NULL:
            procname = ffi.new("char[]",bytes(procname,"utf-8"))
        if libname != ffi.NULL:
            libname = ffi.new("char[]",bytes(libname,"utf-8"))
        '''
        Decorate a function to setup a hook: when a guest goes to execute a basic block beginning with addr,
        the function will be called with args (CPUState, TranslationBlock)
        '''
        def decorator(fun):
            # Ultimately, our hook resolves as a before_block_exec_invalidate_opt callback so we must match its args
            hook_cb_type = ffi.callback("bool (CPUState*, TranslationBlock*, void*)")
            # Inform the plugin that it has a new breakpoint at addr
            
            hook_cb_passed = hook_cb_type(fun)
            if not hasattr(self, "hook_gc_list"):
                self.hook_gc_list = [hook_cb_passed]
            else:
                self.hook_gc_list.append(hook_cb_passed)

            # I don't know what this is/does
            cb_data = ffi.NULL
            hook_number = self.plugins['hooks2'].add_hooks2(hook_cb_passed, cb_data, kernel, \
                procname, libname, trace_start, trace_stop, range_begin,range_end)
            
            self.hook_list[name] = hook_number

            @hook_cb_type # Make CFFI know it's a callback. Different from _generated_callback for some reason?
            def wrapper(*args, **kw):
                return fun(*args, **kw)

            return wrapper
        return decorator
    
    def hook_single_insn(self, name, pc, kernel=False, procname=ffi.NULL, libname=ffi.NULL):
        return self.hook(name, kernel=kernel, procname=procname,libname=libname,range_begin=pc, range_end=pc)
    
         ############# GHIDRA MIXINS ###############
    
    def delete_all_ghidra_memory_segments(self,memory, monitor):
        for block in memory.getBlocks(): 
            memory.removeBlock(block,monitor)


    def populate_ghidra(self,cpu, pc, bridge, namespace, analyze=True):
        globals().update(namespace)
        tid = currentProgram.startTransaction("BRIDGE: Change Memory Sections")
        memory = currentProgram.getMemory()
        self.delete_all_ghidra_memory_segments(memory,monitor)

        def read_memory(cpu, start, size):
            output = b""
            pos = start
            while len(output) < size:
                try:
                    output += self.virtual_memory_read(cpu, pos, 0x100)
                except:
                    output += b"\x00"*0x100
                pos += 0x100
            return output

        names = set()
        for mapping in self.get_mappings(cpu):
            if mapping.file != ffi.NULL:
                name = ffi.string(mapping.file).decode()
            else:
                name = "[unknown]"
            while name in names:
                from random import randint
                name += ":"+hex(randint(0,100000000))
            names.add(name)
            memory.createInitializedBlock(name,toAddr(mapping.base),mapping.size,0,monitor,False)
            memory_read = read_memory(cpu,mapping.base,mapping.size)
            if memory_read:
                memory.setBytes(toAddr(mapping.base), read_memory(cpu,mapping.base, mapping.size))
        if analyze:
            analyzeAll(currentProgram)
        setCurrentLocation(toAddr(pc))
        currentProgram.endTransaction(tid,True)

    def ghidra_decompilation(cpu,pc, bridge):
        #import ghidra.app.decompiler as decomp
        decomp = bridge.remote_import("ghidra.app.decompiler")
        # ## get the decompiler interface
        iface = decomp.DecompInterface()

        # ## decompile the function
        iface.openProgram(currentProgram)
        fn = getFunctionContaining(toAddr(pc))
        d = iface.decompileFunction(fn, 5, monitor)

        ## get the C code as string
        if not d.decompileCompleted():
            code = d.getErrorMessage()
        else:
            code = d.getDecompiledFunction()
            ccode = code.getC()
            code = ccode
        return code
    


# vim: expandtab:tabstop=4:
