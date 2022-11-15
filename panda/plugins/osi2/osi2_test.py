from pandare import Panda, PyPlugin

panda = Panda(generic='x86_64')
@panda.queue_blocking
def driver():
    panda.revert_sync('root')
    prof_file = "/home/rdm/cosi/ubuntu_4.15.0-72-generic_64.json.xz"
    
    panda.load_plugin("osi2", args = {"profile": prof_file})
    panda.load_plugin("osi")
    panda.load_plugin("osi_linux")
    
    #@panda.ppp("osi", "on_asid_change")
    @panda.cb_asid_changed()
    def on_task_change(cpu, old, new):
        current = panda.plugins['osi'].get_current_process(cpu)
        print(f"{current=} | {dir(current)}")
        if current.name != panda.ffi.NULL:
            name = panda.ffi.string(current.name).decode('utf-8', errors='ignore')
        else:
            name = "ERROR"
        print(f"{current.asid=:x} | {current.create_time=:x} | {name=} | {current.pages=} | {current.pid=:x} | {current.ppid=:x} | {current.taskd=:x}")

        current_thread = panda.plugins['osi'].get_current_thread(cpu)
        print(f"{current_thread.pid=:x} | {current_thread.tid=:x}")
        MAX_FD_LIM = 256
        for i in range(0, MAX_FD_LIM):
            fname = panda.plugins["osi_linux"].osi_linux_fd_to_filename(cpu, current, i)
            if fname:
                if res_name := panda.ffi.string(fname).decode('utf-8', errors='ignore'):
                    if res_name != panda.ffi.NULL:
                        print(f"{i=} | {res_name=}")
        return 1
        #panda.plugins['osi2'].get_ts_info(cpu)
        #osi_proc = panda.plugins['osi_linux'].fill_osiproc(cpu, proc, current.taskd)

    print(panda.run_serial_cmd("cat /proc/version"))
    #print(panda.run_serial_cmd("python3 scripts/cli_script.py"))
    panda.end_analysis()

    



panda.run()
