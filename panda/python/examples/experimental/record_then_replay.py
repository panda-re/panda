#!/usr/bin/env python3
# Take a recording, then replay and analyze
from os import remove, path
from pandare import Panda, blocking

arch = "i386"
panda = Panda(generic=arch)

# Make sure we're always saving a new recording
recording_name = "test.recording"
for f in [recording_name+"-rr-nondet.log", recording_name+"-rr-snp"]:
    if path.isfile(f): remove(f)

@blocking
def record_nondet(): # Run a non-deterministic command at the root snapshot, then end .run()
    panda.record_cmd("date; cat /dev/urandom | head -n1 | md5sum", recording_name=recording_name)
    panda.stop_run()

# Collect BBs during both recording and then replay validate that our replay is good
in_replay = False
orig_blocks = set()
replay_blocks = set()
@panda.cb_before_block_exec()
def before_block_exec(env, tb):
    # At each BB's execution in 'find', ensure translation is cached and add to executed_pcs
    global in_replay, orig_blocks, replay_blocks
    pc = panda.current_pc(env)
    if not in_replay:
        orig_blocks.add(pc)
    else:
        replay_blocks.add(pc)

print("======== TAKE RECORDING ========")
print("\n!!!!!! Please wait ~15 seconds for the guest to execute our commands !!!!!\n")
panda.queue_async(record_nondet) # Take a recording
panda.run()
print("======== END RECORDING ========")

print("Observed {} bbs".format(len(orig_blocks)))

print("======== RUN REPLAY ========")
print("Wait a moment for replay to start...")
in_replay = True
panda.run_replay(recording_name) # Load and run the replay
print("======== FINISH REPLAY ========")

orig_block_c = len(orig_blocks)
repl_block_c = len(replay_blocks)
rep_in_orig = sum([1 if x in orig_blocks else 0 for x in replay_blocks])
orig_in_rep = sum([1 if x in replay_blocks else 0 for x in orig_blocks])

print(f"{orig_block_c} blocks are in original execution.\n{repl_block_c} blocks captured in recording.")
print(f"{rep_in_orig} of the recorded blocks are in the original execution.\n{orig_in_rep} of the original blocks are in replay")


@blocking
def second_cmd(): # Run a command at the root snapshot, then end .run()
    panda.revert_sync("root")
    w = panda.run_serial_cmd("whoami")
    assert("root" in w), "Second command failed"
    print("Second command ran successfully")
    panda.stop_run()

print("======= RUN AGAIN ======")
panda.queue_async(second_cmd)
panda.run()
print("======= DONE =========")

for f in [recording_name+"-rr-nondet.log", recording_name+"-rr-snp"]:
    if path.isfile(f): remove(f)
