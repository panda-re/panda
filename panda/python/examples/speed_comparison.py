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
        panda.record_cmd("ls -la",recording_name=recording_name)
        panda.end_analysis()

    panda.run()
    import sys
    sys.exit(0)
else:
    print("recording exists")

from sys import argv

if "C" in argv[1]:
    print("Begin C analysis")
    count = 0
    #@panda.cb_asid_changed()
    def asid_changed(cpu, old_asid, new_asid):
        global count
        if count == 100:
            panda.end_analysis()
        count += 1
        return 0

    panda.load_plugin("cskeleton")
    panda.run_replay(recording_name)
else:
    count = 0
   # @panda.cb_asid_changed(name="qqq")
    def asid_changed(cpu, old_asid, new_asid):
        global count
        if count == 100:
            panda.end_analysis()
        count += 1
        panda.end_analysis()
        return 0

    print("Begin Python analysis.")
    @panda.cb_before_block_exec
    def bbe(cpu, tb):
        pass

    panda.run_replay(recording_name)