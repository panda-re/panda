#!/usr/bin/env python3

from pypanda import *
from sys import argv
import time

# Record some programs running in the guest
# for some programs, register python callbacks

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

bbs_wget = set()
bbs_cat = set()

# Run a command in the guest
@blocking
def my_runcmd():
    panda.revert_sync('root')
    panda.run_serial_cmd("cat /proc/self")
    panda.run_serial_cmd("wget http://google.com")

    # By quitting here main thread can continue executing after panda.run
    # XXX: Need a better way to transfer control back to main thread - maybe via main_loop_wait callbacks?
    panda.run_monitor_cmd("quit")

@panda.cb_before_block_exec(name="test_vmread", procname="wget")
def before_block_execute(env, tb):
    pc = panda.current_pc(env)
    global bbs_wget
    bbs_wget.add(pc)
    return 0

@panda.cb_after_block_exec(name="test_vmread2", procname="cat")
def before_block_execute2(env, tb):
    pc = panda.current_pc(env)
    global bbs_cat
    bbs_cat.add(pc)
    return 0

panda.queue_async(my_runcmd)
start_time = time.time()

panda.run()

analysis_time = time.time()-start_time

# We get here after we quit via the monitor in the async thread
print("\n\nAnalysis completed in {:.2f} seconds.\nResults:".format(analysis_time))
print("  proc  bbcount min_addr max_addr")
print("whoami", hex(len(bbs_wget)), hex(min(bbs_wget)), hex(max(bbs_wget)))
print("   cat", hex(len(bbs_cat)), hex(min(bbs_cat)), hex(max(bbs_cat)))
