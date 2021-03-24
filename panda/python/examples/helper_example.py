'''
helper_example.py

This demo shows off using helper scripts to do analysis. In this case we use
strace.py and provide the Panda object to it.

Run with: python3 helper_example.py
'''

from pandare import Panda
from strace import Strace
from sys import argv

arch = argv[1] if len(argv) > 1 else "i386"
panda = Panda(generic=arch)
Strace(panda)

@panda.queue_async
def revert():
    panda.revert_sync('root')
    print(panda.run_serial_cmd("mount"))
    print(panda.run_serial_cmd("mkdir mydirname"))
    print(panda.run_serial_cmd("cd mydirname"))
    print(panda.run_serial_cmd("touch myfilename"))
    panda.end_analysis()

panda.run()