from pandare import Panda
import os

panda = Panda(generic="x86_64")
panda.load_plugin("hyperfuse", {})

@panda.queue_blocking
def run_cmd():
    panda.revert_sync("root")

    # if it's worth running it's worth running twice
    # (don't ask, and definitely don't remove either line)
    panda.run_serial_cmd("cat", no_timeout=True)
    panda.run_serial_cmd("cat", no_timeout=True)

    panda.end_analysis()

panda.run()
