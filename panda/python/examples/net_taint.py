#!/usr/bin/env python3

# Taint incoming network data - WIP

import os
from panda import Panda, blocking, ffi
from panda.x86.helper import * # XXX i386 names but they line up with x86_64

args = [
    "-nographic",
    "-net", "nic,netdev=net0",
    "-netdev", "user,id=net0,hostfwd=tcp::4443-:443,hostfwd=tcp::4480-:80",
    ]

'''
# panda-re.mit.edu qcow
qcf="/home/andrew/.panda/bionic-server-cloudimg-amd64.qcow2"
panda = Panda(arch="x86_64",
        expect_prompt=rb"root@ubuntu:.*#",
        qcow=qcf,
        mem="1G", extra_args=args)
panda.set_os_name("linux-64-ubuntu:4.15.0-72-generic")
'''

panda = Panda(generic="i386", extra_args=args)
panda.load_plugin("syscalls2")
panda.load_plugin("taint2")
panda.load_plugin("tainted_branch", {"summary": False})
panda.set_pandalog("net.plog")


#panda.load_plugin("file_taint", {"filename":"/root/.bashrc", "verbose": False})

# Whenever the guest 'accepts' on a socket it gets a new file-descriptor
# Data read from that fd is considered network data and we taint it.

net_fds = set()
taint_idx = 0 # Each request increments

# TODO: expose a port-specific filter
@panda.ppp("syscalls2", "on_sys_accept4_return")
def on_sys_accept_return(cpu, pc, sockfd, addr, addrLen, junk):
    newfd = cpu.env_ptr.regs[R_EAX]
    print(f"Accept on {sockfd}, new FD is {newfd}")
    net_fds.add(newfd)

# TODO: we should hook calls to vfs_read instead of syscalls
@panda.ppp("syscalls2", "on_sys_read_return")
def on_sys_read_return(cpu, pc, fd, buf, count):
    # XXX: taint labels are applied in main_loop_wait so this might be completley
    # broken depending on when that runs (hopefully at the return?)
    # This needs testing. See taint_mixins.py:37
    global taint_idx

    if fd in net_fds:
        bytes_written = cpu.env_ptr.regs[R_EAX]
        data = panda.virtual_memory_read(cpu, buf, bytes_written)

        if not b'GET' in data and not b'POST' in data:
            print(f"Not tainting buffer: {repr(data)}")
            return # Don't taint non HTTP. Might have issues if requested get buffered

        print(f"Tainting {bytes_written}-byte buffer from fd {fd} with label {taint_idx}",
                repr(data)[:30], "...")

        # Label each tainted (physical) address
        for taint_vaddr in range(buf, buf+bytes_written):
            taint_paddr = panda.virt_to_phys(cpu, taint_vaddr) # Physical address
            panda.taint_label_ram(taint_paddr, taint_idx)

        # Increment label for next request
        taint_idx += 1
    else:
        # SUPER HACKY - but syscalls aren't finidng the accept
        bytes_written = cpu.env_ptr.regs[R_EAX]
        data = panda.virtual_memory_read(cpu, buf, bytes_written)

        if b'GET' in data or b'POST' in data:
            print(f"Tainting {bytes_written}-byte buffer from fd {fd} with label {taint_idx}",
                    repr(data)[:30], "...")

            # Label each tainted (physical) address
            for taint_vaddr in range(buf, buf+bytes_written):
                taint_paddr = panda.virt_to_phys(cpu, taint_vaddr) # Physical address
                panda.taint_label_ram(taint_paddr, taint_idx)

            # Increment label for next request
            taint_idx += 1


@panda.ppp("syscalls2", "on_sys_close_enter")
def on_sys_close_enter(cpu, pc, fd):
    if fd in net_fds:
        net_fds.remove(fd)


# WIP. CFFI Can't typedef structures with unions, like addrs
# So here we replace `val` with a uint64_t 'addr_val'
ffi.cdef("""
        typedef struct {
            AddrType typ;
            uint64_t addr_val;
            uint16_t off;
            AddrFlag flag;
        } FakeAddr;
""")

ffi.cdef('typedef void (*on_branch2_t) (FakeAddr, uint64_t);', override=True) # XXX WIP
ffi.cdef('void ppp_add_cb_on_branch2(on_branch2_t);') # Why don't we autogen this? Are we not translating the macros into fn defs?
# On tainted branches
@panda.ppp("taint2", "on_branch2")
def tainted_branch(addr, size):
    #print("TAINTED BRANCH")
    try:
        # XXX: How can we use CFFI to make this 'LADDR' instead of 4
        assert(addr.typ == 4), "Tainted branch Expected an LADDR"
        laddr = addr.addr_val # It's an LAddr

        # For each addres between addr and addr + size, check if it's tainted.
        # If so, store tain labels in tainted

        tainted = []
        real_addr = addr.addr_val # Pull out actual laddr
        for offset in range(0, size):
            if panda.taint_check_laddr(real_addr, offset):
                tq = panda.taint_get_laddr(laddr, offset)
                taint_labels = tq.get_labels()
                tainted.append(taint_labels)

        #assert(len(tainted)), "No data was actually tainted?"

        if len(tainted):
            cpu = panda.get_cpu()
            pc = panda.current_pc(cpu)
            print(f"Tainted branch at 0x{pc:x}: taint labels: {tainted}")
    except Exception as e:
        panda.end_analysis()
        raise e


@blocking
def run_cmd():
    print("\nSetting up...")
    panda.revert_sync("root")
    print("\nREADY")
    print(panda.run_serial_cmd("echo 'hello' | nc -vlp 80", no_timeout=True))
    print("\nFinished recving")
    panda.end_analysis()


panda.queue_async(run_cmd)
import time
start = time.time()
panda.run()
delta = time.time() - start
print(f"Live execution with taint took {delta} seconds")
