#!/usr/bin/env python3
import sys
from panda import *
from panda.extras.file_faker import FileFaker, FakeFile, Foo

arch = sys.argv[1] if len(sys.argv) > 1 else "i386"
panda = Panda(generic=arch)

'''
# Create a fake file with simple contents
myFakeFile = FakeFile("hello world\n")

# Load plugin to manage fake files and replaces accesses
# of /foo with our fake file
faker = FileFaker(panda)
faker.replace_file("/foo", myFakeFile)
'''

# Testing - why doesn't this work?
faker = FileFaker(panda)
faker.rename_file("/foo", "/etc/passwd")

'''
@blocking
def read_it():
    panda.revert_sync('strace')
    #data = panda.run_serial_cmd("strace -f sh -c 'echo hi > /foo'")
    data = panda.run_serial_cmd("echo hi > /foo")
    print(data)
    panda.end_analysis()

panda.queue_async(read_it)
'''

@blocking
def nop():
    panda.end_analysis()

panda.queue_async(nop)
panda.run()

del faker

#print("DO DELETE")
#del faker
#print(faker)
