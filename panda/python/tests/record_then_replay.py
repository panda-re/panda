#!/usr/bin/env python3
# Take a recording, then replay with analysis, then revert vm and run more commands
from sys import argv
from os import remove, path
from pandare import Panda

# Default arch is i386, but others can be used
arch = argv[1] if len(argv) > 1 else "i386"
panda = Panda(generic=arch)

# Make sure we're always saving a new recording
recording_name = "test.recording"
for f in [recording_name+"-rr-nondet.log", recording_name+"-rr-snp"]:
    if path.isfile(f): remove(f)

successes = [False, False]

####################### Recording ####################
@panda.queue_blocking
def record_nondet(): # Run a non-deterministic command at the root snapshot, then end .run()
    panda.record_cmd("date; cat /dev/urandom | head -n30 | md5sum", recording_name=recording_name)
    global successes
    successes[0] = True
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

print("Taking recording (wait ~15s)...")
panda.run()
print("Done with recording. Observed {} bbs".format(len(orig_blocks)))

####################### Replay ####################
print("Starting replay. Please wait a moment...")
in_replay = True
panda.load_plugin('asidstory') # XXX: dependes on OSI
panda.run_replay(recording_name) # Load and run the replay
print("Finished replay")
panda.unload_plugin('asidstory') # Should now create 'asidstory' file

# Check ASIDSTORY output
assert(path.isfile('asidstory')), "Asidstory didn't create output"
with open('asidstory') as f:
    data = f.read()
    assert("date" in data), "Unexpected output from asidstory"
    assert(" md5sum " in data), "Unexpected output from asidstory"

orig_block_c = len(orig_blocks)
repl_block_c = len(replay_blocks)
rep_in_orig = sum([1 if x in orig_blocks else 0 for x in replay_blocks])
orig_in_rep = sum([1 if x in replay_blocks else 0 for x in orig_blocks])

print(f"{orig_block_c} blocks are in original execution.\n{repl_block_c} blocks captured in recording.")
print(f"{rep_in_orig} of the recorded blocks are in the original execution.\n{orig_in_rep} of the original blocks are in replay")

# Some divergence  (1%) is allowed because we're a bit imprecise on the edges where we start and stop
assert(rep_in_orig > 0.99*repl_block_c), "Not enough blocks from replay were in original"
assert(orig_in_rep > 0.99*orig_block_c), "Not enough blocks from original were in replay"

####################### Switch to live ####################

@panda.queue_blocking
def second_cmd(): # Run a command at the root snapshot, then end .run()
    panda.revert_sync("root")
    w = panda.run_serial_cmd("whoami")
    assert("root" in w), "Second command failed: Got incorrect username from guest"
    print("Second command ran successfully")

    global successes
    successes[1] = True

    panda.stop_run()

print("Now run a new command")
panda.run()
print("Finished")

####################### Cleanup & Check results  ####################

# Count RR files that were created
rr_file_count = 0
for f in [recording_name+"-rr-nondet.log", recording_name+"-rr-snp"]:
    if path.isfile(f):
        rr_file_count+=1
        remove(f)

# Also delete asidstory output
remove('asidstory')

assert(rr_file_count == 2), "Didn't create expected replay files"
assert(successes[0]), "First recording failed to run"
assert(successes[1]), "Second recording failed to run"

