#!/usr/bin/env python3
'''
example_multiple_callbacks.py

This example registers the before_block_exec and after_block_exec callbacks and
prints a message and sleeps each time the callback is hit.

Run with: python3 example_multiple_callbacks.py
'''
from time import sleep
from sys import argv
from pandare import Panda

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

recording_name = "test.recording"

ctr = 0
@panda.cb_before_block_exec
def my_before_block_execute(cpustate, transblock):
    print("before block in python... sleeping 1s")
    sleep(1)

@panda.cb_after_block_exec
def my_after_block_execute(cpustate,transblock,exit):
    print("after block in python")
    global ctr
    ctr +=1
    if ctr > 100:
        panda.end_analysis()

panda.run()
