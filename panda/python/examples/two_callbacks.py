#!/usr/bin/env python3
'''
two_callbacks.py

On a live system, collect basic blocks as we run cat and wget.

Run with: python3 two_callbacks.py
'''

import time
from sys import argv
from pandare import Panda, blocking

# Record some programs running in the guest
# for some programs, register python callbacks

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

bbs_wget = set()
bbs_cat = set()

# Run a command in the guest
@panda.queue_blocking
def my_runcmd():
    panda.revert_sync('root')
    panda.run_serial_cmd("cat /proc/self")
    panda.run_serial_cmd("wget http://google.com")
    panda.end_analysis()

@panda.cb_before_block_exec(procname="wget")
def before_block_execute(env, tb):
    pc = panda.current_pc(env)
    global bbs_wget
    bbs_wget.add(pc)

@panda.cb_after_block_exec(procname="cat")
def before_block_execute2(env, tb, exit):
    pc = panda.current_pc(env)
    global bbs_cat
    bbs_cat.add(pc)

start_time = time.time()

panda.run()

analysis_time = time.time()-start_time

# We get here after we quit via the monitor in the async thread
print("\n\nAnalysis completed in {:.2f} seconds.\nResults:".format(analysis_time))
print("  proc  bbcount min_addr max_addr")
print("whoami ", hex(len(bbs_wget)), hex(min(bbs_wget)), hex(max(bbs_wget)))
print("   cat ", hex(len(bbs_cat)), hex(min(bbs_cat)), hex(max(bbs_cat)))
