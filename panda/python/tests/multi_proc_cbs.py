#!/usr/bin/env python3
from sys import argv
from os import path
from pandare import Panda

# Run toy in a linux guest- Assert that the process toy runs as well as "ata_id" which is
# a linux process that seems to always be running in our recordings

# Toy is precompiled for i386 so we only test for that. Should eventually try all supported archs
panda = Panda(generic="i386")

# Take a recording of toy running in the guest if necessary
if not path.isfile("toy-rr-snp"):
    @panda.queue_blocking
    def run_toy():
        panda.record_cmd("toy/toy toy/testsmall.bin", "toy", recording_name="toy")
        panda.stop_run()

    print("Generating toy replay")
    panda.queue_async(run_toy)
    panda.run()

hit_toy = False
hit_ata = False
hit_always = False

@panda.cb_before_block_exec(procname="ata_id")
def ata_before_block(env, tb):
    global hit_ata
    if not hit_ata:
        hit_ata = True

@panda.cb_before_block_exec(procname="toy")
def toy_before_block(env, tb):
    global hit_toy
    if not hit_toy:
        hit_toy = True

@panda.cb_before_block_exec
def always_before_block(env, tb):
    global hit_always
    if not hit_always:
        hit_always = True

panda.run_replay("toy")

print("TOY:", hit_toy)
print("ATA:", hit_ata)
print("ALL:", hit_always)
assert (hit_toy and hit_ata and hit_always),  "Callbacks didn't all run"
print("Success! All three callbacks ran as anticipated")
