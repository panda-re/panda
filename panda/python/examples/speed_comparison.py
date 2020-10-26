from pandare import Panda, blocking
from os.path import exists

panda = Panda(generic="x86_64")
recording_name = "speed_compare"

if not exists(recording_name + "-rr-snp"):
    print("Taking recording")
    @panda.queue_blocking
    def take_recording():
        panda.record(recording_name, snapshot_name="root")
        panda.run_serial_cmd("whoami")
        panda.run_serial_cmd("ls -la")
        panda.end_record()

    panda.run()
else:
    print("Recording exists")


print("Begin C analysis")
panda.load_plugin("cskeleton")
panda.run_replay(recording_name)

print("Begin Python analysis.")
@panda.cb_before_block_exec
def bbe(cpu, tb):
    pass

panda.run_replay(recording_name)