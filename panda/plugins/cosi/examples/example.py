from pandare import Panda, PyPlugin

panda = Panda(generic='x86_64')
@panda.queue_blocking
def driver():
    panda.revert_sync('root')
    panda.load_plugin("cosi")

    @panda.cb_asid_changed()
    def on_task_change(cpu, old, new):
        try:
            cosi_current = panda.plugins['cosi'].get_current_cosiproc(cpu)
            print(f"It's-a me, cosi: {cosi_current.name}")
        except:
            pass
        
        return 1

    print(panda.run_serial_cmd("cat /proc/version | grep 'test'"))
    panda.end_analysis()

panda.run()
