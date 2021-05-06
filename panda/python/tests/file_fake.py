#!/usr/bin/env python3
# Test to ensure the file_hook plugin is working

import sys
from pandare import *
from pandare.extras import FileFaker, FakeFile

arch = sys.argv[1] if len(sys.argv) > 1 else "i386"
panda = Panda(generic=arch)

# Replace all syscalls that reference /foo with a custom string
fake_str = "Hello world. This is data generated from python!"
faker = FileFaker(panda)
faker.replace_file("/foo", FakeFile(fake_str))

new_str = "This is some new data"

@blocking
def read_it():
    global new_str

    panda.revert_sync('root')
    data = panda.run_serial_cmd("cat /foo")
    assert(fake_str in data), f"Failed to read fake file /foo: {data}"

    panda.run_serial_cmd(f'echo {new_str} > /foo')
    data = panda.run_serial_cmd("cat /foo")
    assert(new_str in data), f"Failed to update fake file /foo: {data}. Expected: {new_str}"

    panda.end_analysis()

panda.queue_async(read_it)
panda.run()
print("Successfully faked file /foo")
