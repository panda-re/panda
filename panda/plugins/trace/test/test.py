import os
from pandare import Panda

arch = 'x86_64'
#panda = Panda(generic=arch, extra_args="-d in_asm".split(" "))
panda = Panda(generic=arch)

if not os.path.isfile(f'test-{arch}-rr-nondet.log'):
    print("Generating recording")
    @panda.queue_blocking
    def driver():
        panda.record_cmd("whoami", recording_name=f"test-{arch}")
        panda.end_analysis()

    panda.run()

#panda.load_plugin("trace", {'log': f'trace_{arch}.txt'})
panda.load_plugin("trace", {'log': f'trace_{arch}.txt', 'target': 'whoami'})
#panda.load_plugin("trace", {'log': f'trace_full_{arch}.txt'})

panda.run_replay(f"test-{arch}")

print(f"Trace saved to: trace_{arch}.txt")
