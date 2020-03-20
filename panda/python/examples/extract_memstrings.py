#!/usr/bin/env python3

# This plugin registers the virt_mem_after_write callback and attempts to find strings in memory buffers.

from sys import argv
from string import ascii_letters
from os import remove, path
from panda import Panda, ffi, blocking

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

# Make sure we're always saving a new recording
recording_name = "mem_test.recording"
for f in [recording_name+"-rr-nondet.log", recording_name+"-rr-snp"]:
    if path.isfile(f): remove(f)

@blocking
def my_record_cmd(): # Run a non-deterministic command at the root snapshot, then end .run()
    panda.record_cmd("wget google.com", recording_name=recording_name)
    panda.stop_run()

print("Take recording...")
panda.queue_async(my_record_cmd)
panda.run()

print("Analyze replay...")
string_buffer = ""

# After we see a virt mem write, try to build up a human-readable string. If we build
# up a big enough string, print it
@panda.cb_virt_mem_after_write()
def virt_mem_after_write(env, pc, addr, size, buf):
    global string_buffer
    try:
        py_str = panda.virtual_memory_read(env, addr, size, fmt='str').decode("utf-8", "strict")
    except UnicodeDecodeError: #
        string_buffer = ""
        return 0

    string_buffer += "".join([x for x in py_str if x in ascii_letters or x in [' ', '\n']])

    if len(string_buffer) > 80:
        print(string_buffer)
        string_buffer = ""

    if len(string_buffer) < size/2:
        string_buffer = ""
    return 0

panda.enable_memcb()
panda.run_replay(recording_name)
