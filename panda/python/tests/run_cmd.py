#!/usr/bin/env python3

# This test validates that run_serial_cmd works
# both in terms of getting the correct response
# but also for running multiple commands sequentially

from pandare import Panda
panda = Panda(generic="i386")

@panda.queue_blocking
def run_cmds():
    panda.revert_sync("root")
    
    for cur_size in range(1, 300):
        buf = '1234567890'*(cur_size//10) + '1234567890'[:cur_size % 10]
        assert(len(buf) == cur_size), "Test is broken"

        resp = panda.run_serial_cmd(f"echo {buf}")

        # Check length
        assert(len(resp) == len(buf)), f"Test {cur_size}: Echo'd {len(buf)} characters but got {len(resp)} back"

        # Check contents
        for j in range(len(buf)):
            if resp[j] != buf[j]:
                raise ValueError(f"Test {cur_size}: Response character {j} was {repr(resp[j])} instead of an {buf[j]}")

    panda.end_analysis()

panda.run()
