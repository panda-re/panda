from pandare import Panda, PyPlugin

panda = Panda(generic='x86_64')
@panda.queue_blocking
def driver():
    panda.revert_sync('root')
    panda.load_plugin("cosi")

    @panda.cb_asid_changed()
    def on_task_change(cpu, old, new):
        cosi_current = panda.cosi.current_process()
        if cosi_current == None:
            return 0
        print(f"Read CosiProc info: {cosi_current.get_name()} @ 0x{cosi_current.inner.addr:x}")   
        return 1

    print(panda.run_serial_cmd("cat /proc/version"))
    panda.end_analysis()

panda.run()
