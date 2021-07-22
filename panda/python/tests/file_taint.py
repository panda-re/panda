from pandare import Panda
from os import remove
from sys import artv

# Default arch is i386, but others can be used
arch = argv[1] if len(argv) > 1 else "i386"
panda = Panda(generic=arch)

# Make sure we're always saving a new recording
recording_name = "filetaint.recording"
for f in [recording_name+"-rr-nondet.log", recording_name+"-rr-snp"]:
    if path.isfile(f): remove(f)

success = False

@panda.queue_blocking
def driver():
    panda.record_cmd("cat /etc/passwd | wc -l", recording_name=recording_name)
    panda.stop_run()

panda.run() # take recording

@panda.ppp("taint2", "on_taint_change")
def taint_change(*args):
    global success
    success = True
    panda.end_analysis()

panda.load_plugin("file_taint", {"filename": "/etc/passwd"})
panda.run_replay("filetaint")

assert(success), "Taint callback was not triggered when it should have been"
