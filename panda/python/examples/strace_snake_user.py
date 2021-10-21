'''
This demo shows off using a pypanda plugin to do analysis. In this case we use
strace.py from strace.py

Run with: python3 pypanda_plugin_user.py
'''

from pandare import Panda
from sys import argv
from strace import Strace

arch = argv[1] if len(argv) > 1 else "i386"
panda = Panda(generic=arch)

panda.pyplugins.load(Strace)

@panda.queue_blocking
def revert():
    panda.revert_sync('root')
    print(panda.run_serial_cmd("mount"))
    print(panda.run_serial_cmd("mkdir mydirname"))
    print(panda.run_serial_cmd("cd mydirname"))
    print(panda.run_serial_cmd("touch myfilename"))
    panda.end_analysis()

panda.run()
