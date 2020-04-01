#!/usr/bin/env python3
# Test to ensure the file_hook plugin is working

import sys
from panda import *
from panda.extras.file_faker import FileFaker, FakeFile

arch = sys.argv[1] if len(sys.argv) > 1 else "i386"
panda = Panda(generic=arch)

# Replace all syscalls that reference /foo with a custom string
fake_str = "Hello world. This is data generated from python!"
faker = FileFaker(panda)
faker.replace_file("/foo", FakeFile(fake_str))

@blocking
def read_it():
    panda.revert_sync('root')
    data = panda.run_serial_cmd("cat /foo")
    assert(fake_str in data), f"Failed to read fake file /foo: {data}"
    panda.end_analysis()

panda.queue_async(read_it)
panda.run()
print("Successfully faked file /foo")
