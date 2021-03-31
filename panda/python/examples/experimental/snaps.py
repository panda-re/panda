#!/usr/bin/env python3
'''
snaps.py

A simple demo script of precise control over taking and restoring
snapshots with pypanda.  Makes use of prior knowledge of what code
will be executed when we revert to the 'root' snapshot in the
indicated qcow.

1. A after machine init callback lets us start that guest and
immediate revert it to the snapshot 'root' which is a booted machine
logged in to the root account.

2. A before block exec callback lets us wait until we encounter a very
particular pc (0xc101dfec) which we only knew about bc we ran qemu -d
in_asm before.  At this pc we take a snapshot.  This callback actually
contains a little state machine.  After we have taken the snapshot, we
are in state 3, where we increment a counter with each call, i.e. for
each new basic block we execute.  After 10 blocks, we revert to the
snapshot at 0xc101dfec.

Obviously there are more interesting uses for this kind of thing.  Two
important things to notice.  First, we can take a snapshot that will
in fact revert to a specific block's start pc.  Second, when we
revert, we don't keep executing any code.  We snap back to exactly
that bloc.

Run with: python3 snaps.py

'''

import os
from sys import argv,exit
from pandare import Panda, blocking


# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

state = 0 # before snapshot load

@blocking
def init():
    global state
    panda.delvm_sync("newroot")
    panda.revert_sync("root")
    state = 1

nt = 0
blocks = []

@panda.cb_before_block_exec()
def before_block_exec(env,tb):
    global nt
    global state
    global blocks
    if state == 0:
        return

    pc = panda.current_pc(env)

    if (state == 1):
        assert (pc == 0xc12c4648)
        state = 2

    if (state == 2 and pc == 0xc101dfec):
        print ("\nCreating 'newroot' snapshot at 0xc101dfec")
        panda.snap("newroot")
        state = 3
        return

    if state == 3:
        if len(blocks) <= nt: # First time: capture ordered list of PCs for basic blocks
            print(nt,hex( pc))
            blocks.append(pc)
        elif blocks[nt] != pc: # Subsequent execs, fail if we ever diverge from expected
            print("Divergence in the {}th block. Expected 0x{:x}, but got 0x{:x}".format(nt, blocks[nt], pc))
            panda.end_analysis()
            state = 4

        nt = nt + 1

        if nt == 10:
            print("Block sequences matches expected value!\nRestoring 'newroot' snapshot")
            panda.revert_async("newroot")
            nt = 0
        return

    if state == 4:
        pass # While an async command is queued, don't do anything

panda.disable_tb_chaining()
panda.queue_async(init)
panda.run()
