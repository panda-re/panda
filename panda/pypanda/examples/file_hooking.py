#!/usr/bin/env python3
from sys import argv
from os import path
from panda import Panda, blocking, ffi
from panda.x86.helper import * # XXX omg these are 32-bit names

arch = "x86_64" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

interesting_file_name = b"fakefile"

panda.set_os_name("linux-64-ubuntu")
panda.load_plugin("callstack_instr", args={"stack_type": "asid"})
panda.require("syscalls2")

file_info = None

# TODO: move PPP decorator into core panda
def ppp(plugin_name, attr):
    def inner(func):
        panda.plugins[plugin_name].__getattr__(attr)(func)
        return func
    return inner

# Read

cb_name = "on_sys_read_return"
cb_args = "CPUState *, target_ulong, uint32_t, uint64_t, uint32_t"
ffi.cdef(f"void ppp_add_cb_{cb_name}(void (*)({cb_args}));")

@ppp("syscalls2", f"ppp_add_cb_{cb_name}")
@ffi.callback(f"void({cb_args})")
def on_sys_read_return(cpustate, pc, fd, buf, count):
    global file_info
    if file_info:
        cr3, fd1, cnt = file_info
        if cr3 == cpustate.env_ptr.cr[3] and fd == fd1:
            returned = cpustate.env_ptr.regs[R_EAX]
            r = ffi.cast('signed int', returned)
            #print(f"Read from FD={fd} into buffer 0x{buf:x} up to size {count}. Was returning {int(r)}. Cnt is {cnt}")

            NUM_REPLAYS = 4
            if cnt == NUM_REPLAYS: # After X times, we write no data and return 0 to indicate EOF?
                #print("READ: EOF")
                cpustate.env_ptr.regs[R_EAX] = 0  # No more bytes, Guest should stop reading
            else:
                #print("READ: write fake data")
                file_contents  = f"This is data from read #{cnt}!\n".encode('utf8')
                if cnt == NUM_REPLAYS-1: # Last iteration, add newline and null terminator
                    file_contents += b"\n"

                panda.virtual_memory_write(cpustate, buf, file_contents)
                cpustate.env_ptr.regs[R_EAX] = len(file_contents)

            file_info = cr3, fd1, cnt+1


# Close
cb_name = "on_sys_close_return"
cb_args = "CPUState *, target_ulong, uint32_t"
ffi.cdef(f"void ppp_add_cb_{cb_name}(void (*)({cb_args}));")

@ppp("syscalls2", f"ppp_add_cb_{cb_name}")
@ffi.callback(f"void({cb_args})")
def on_sys_close_return(cpustate, pc, fd):
    global file_info
    if file_info and fd == file_info[1]:
        #print("CLOSE: hide error")
        cpustate.env_ptr.regs[R_EAX] = 0  # No more bytes, Guest should stop reading



# Open
cb_name = "on_sys_open_return"
cb_args = "CPUState *, target_ulong, uint64_t, int32_t, uint32_t"
ffi.cdef(f"void ppp_add_cb_{cb_name}(void (*)({cb_args}));")

@ppp("syscalls2", f"ppp_add_cb_{cb_name}")
@ffi.callback(f"void({cb_args})")
def on_sys_open_return(cpustate, pc, filename, flags, mode):
    global file_info
    fname = panda.virtual_memory_read(cpustate, filename, 100)
    fname_total = fname[:fname.find(b'\x00')]
    if interesting_file_name in fname_total:
        # Here we make up a new FD - note that the guest identifies this as invalid very quickly?
        #print(f"on_sys_open_enter: {fname_total}")
        global info
        if cpustate.env_ptr.regs[R_EAX] > 255: # hack for -1
            #print("OPEN: hide error, give fake FD of 99")
            cpustate.env_ptr.regs[R_EAX] = 99
        file_info = cpustate.env_ptr.cr[3], cpustate.env_ptr.regs[R_EAX], 0


# stat

# Unnecessary but useful if we want to mess with stat data structure?
# Hand made for CFFI but I guess it's unnecessary. Could remove
stat_h = """typedef struct stat {
    // Assuming long is 8, int is 4
    long st_dev;		/* Device.  */
    long st_ino;		/* File serial number.	*/
    long st_nlink;		/* Link count.  */
    int st_mode;		/* File mode.  */
    int st_uid;		/* User ID of the file's owner.	*/
    int st_gid;		/* Group ID of the file's group.*/
    int __pad0;
    long st_rdev;		/* Device number, if device.  */
    long st_size;			/* Size of file, in bytes.  */
    long st_blksize;	/* Optimal block size for I/O.  */
    //char st_atim[10];
    char st_mtim[10];
    char st_ctim[10];
  } stat;
"""
#ffi.cdef(stat_h)
        
cb_name = "on_sys_newfstat_return"
cb_args = "CPUState *, target_ulong, uint32_t, uint64_t"
ffi.cdef(f"void ppp_add_cb_{cb_name}(void (*)({cb_args}));")

@ppp("syscalls2", f"ppp_add_cb_{cb_name}")
@ffi.callback(f"void({cb_args})")
def on_sys_newfstat_return(cpustate, pc, fd, statbuf):
    global file_info

    if file_info:
        cr3, fd1, cnt = file_info
        if cr3 == cpustate.env_ptr.cr[3] and fd == fd1:
            cpustate.env_ptr.regs[R_EAX] = 0 # No error

# fadvise64 - Strace shows it's unhappy but it doesn't affect output so maybe we ignore it?
'''
cb_name = "on_sys_fadvise64_return"
cb_args = "CPUState *, target_ulong, uint32_t, uint32_t, uint32_t"
ffi.cdef(f"void ppp_add_cb_{cb_name}(void (*)({cb_args}));")

@ppp("syscalls2", f"ppp_add_cb_{cb_name}") # Runs after our named CB
@ffi.callback(f"void({cb_args})")
def on_fadvise(cpustate, pc, fd, a, flags):
    global file_info
    if file_info:
        cr3, fd1, cnt = file_info
        if cr3 == cpustate.env_ptr.cr[3] and fd == fd1:
            returned = cpustate.env_ptr.regs[R_EAX]
            r = ffi.cast('signed int', returned)
            print(f"MASK old ret: {r} instead ret 0")
            cpustate.env_ptr.regs[R_EAX] = 0 # No error

'''

@blocking
def mycmd():
    panda.revert_sync("root")
    print("GUEST RUNNING COMMAND:\n\n# cat fakefile\n" + panda.run_serial_cmd("cat fakefile"))
    #panda.revert_sync("strace")
    #print(panda.run_serial_cmd("strace -v cat fakefile"))
    panda.end_analysis()

panda.queue_async(mycmd)
panda.run()
