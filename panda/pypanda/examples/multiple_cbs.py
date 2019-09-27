#!/usr/bin/env python3
'''
example_multiple_callbacks.py

This example registers the before_block_exec and after_block_exec callbacks and
prints a message and sleeps each time the callback is hit.

Run with: python3 example_multiple_callbacks.py
'''
from time import sleep
from sys import argv, path
path.append("..")
from panda import Panda

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

recording_name = "test.recording"

ctr = 0
@panda.cb_before_block_exec()
def my_before_block_execute(cpustate, transblock):
    print("before block in python")
    sleep(0.01) # XXX panda bug? we don't hit after block exec if we sleep for too long (1s+) here (reasonable in a live recording, less reasonable in a replay)
    return 0

@panda.cb_after_block_exec()
def my_after_block_execute(cpustate,transblock,exit):
    print("after block in python")
    global ctr
    ctr +=1
    if ctr > 100:
        panda.end_analysis()
    return 0

panda.run()
