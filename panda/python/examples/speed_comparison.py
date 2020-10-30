from pandare import Panda, blocking
from os.path import exists
from time import sleep
from pandare.qcows import SUPPORTED_IMAGES

panda = Panda(generic="i386")


recording_name = "speed_compare"
if not exists(recording_name + "-rr-snp"):
    print("Taking recording")

    @panda.queue_blocking
    def run():
        panda.record_cmd(command="cat /a",recording_name=recording_name)

    panda.run()
else:
    print("Recording exists")

import os
os._exit(0)

print("Begin C analysis")
sleep(10)
panda.load_plugin("cskeleton")
panda.run_replay(recording_name)

print("Begin Python analysis.")
sleep(10)
@panda.cb_before_block_exec
def bbe(cpu, tb):
    print("hello")
    pass

panda.run_replay(recording_name)