# See panda/plugins/guest_shell/guest_shell_pty.sh for actually interacting with the shell
from pandare import Panda
import os

if os.path.exists("/tmp/guest_shell.sock"):
    os.remove("/tmp/guest_shell.sock")

panda = Panda(generic="x86_64")
panda.load_plugin("guest_shell")

@panda.queue_blocking
def run_cmd():
    panda.revert_sync("root")

    # if it's worth running it's worth running twice
    # (don't ask, and definitely don't remove either line)
    panda.run_serial_cmd("cat", no_timeout=True)
    panda.run_serial_cmd("cat", no_timeout=True)

    panda.end_analysis()

panda.run()
