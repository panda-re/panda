#!/usr/bin/env python3
'''
fake_files.py

This example replaces a file with a fake file.

Run with: python3 fake_files.py
'''
import sys
from pandare import Panda
from pandare.extras import FileFaker, FakeFile

arch = sys.argv[1] if len(sys.argv) > 1 else "i386"
panda = Panda(generic=arch)

# Create a fake file with simple contents
myFakeFile = FakeFile("hello world\n")

# Load plugin to manage fake files and replaces accesses
# of /foo with our fake file
faker = FileFaker(panda)
faker.replace_file("/foo", myFakeFile)

@panda.queue_blocking
def read_it():
    panda.revert_sync('root')
    hello_world = panda.run_serial_cmd("cat /foo")
    print("hello word == ", hello_world)
    panda.run_serial_cmd("echo hi > /foo")
    hi = panda.run_serial_cmd("cat /foo")
    print("hi ==", hi)
    panda.end_analysis()

panda.run()

# Shutdown our faker class to dump fake file states at end
faker.close()
