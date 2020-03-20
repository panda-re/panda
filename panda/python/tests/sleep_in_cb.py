#!/usr/bin/env python3
from time import sleep
from panda import Panda, blocking

'''
Blocking function hangs
but callback can still request end_analysis
and end call to panda.run
'''

panda = Panda(generic='i386')
sleeping_started = False
sleeping_ended = False

@blocking
def hang():
    '''
    This function should start but never finish because the
    before block exec callback should end_analysis which
    preempts this
    '''
    global sleeping_started, sleeping_ended
    sleeping_started = True
    sleep(1000)
    sleeping_ended = True
    panda.end_analysis()

@panda.cb_before_block_exec
def before_block_execute(cpustate, transblock):
    if sleeping_started:
        panda.end_analysis()

panda.queue_async(hang)
panda.run()
print("Run finished. Ready to exit...")
assert(sleeping_started)
assert(not sleeping_ended)
