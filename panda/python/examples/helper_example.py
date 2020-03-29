from panda import *
from strace import Strace

panda = Panda(generic="i386")
Strace(panda)

@blocking
def revert():
    panda.revert_sync('root')
    print(panda.run_serial_cmd("mount"))
    print(panda.run_serial_cmd("mkdir mydirname"))
    print(panda.run_serial_cmd("cd mydirname"))
    print(panda.run_serial_cmd("touch myfilename"))
    panda.end_analysis()

panda.queue_async(revert)
panda.run()
