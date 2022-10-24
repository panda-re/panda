from pandare import Panda

panda = Panda(generic="x86_64")
panda.load_plugin("guest_plugin_example")

@panda.queue_blocking
def run_cmd():
    panda.revert_sync("root")
    panda.run_serial_cmd("cat", no_timeout=True)
    panda.run_serial_cmd("cat", no_timeout=True)
    panda.end_analysis()

panda.run()
