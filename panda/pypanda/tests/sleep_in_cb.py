#!/usr/bin/env python3
from time import sleep
from panda import Panda, blocking

'''
Blocking function hangs
but callback can still request end_analysis
and end call to panda.run
'''

panda = Panda(generic='i386')
started_sleeping = False

@blocking
def hang():
    global started_sleeping
    started_sleeping = True
    sleep(1000)
    panda.end_analysis()

@panda.cb_before_block_exec
def before_block_execute(cpustate, transblock):
    if started_sleeping:
        panda.end_analysis()
    return 0

panda.queue_async(hang)
panda.run()
print("Run finished. Ready to exit...")
