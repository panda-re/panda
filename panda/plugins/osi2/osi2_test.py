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
        return 1
        #panda.plugins['osi2'].get_ts_info(cpu)
        #osi_proc = panda.plugins['osi_linux'].fill_osiproc(cpu, proc, current.taskd)

    print(panda.run_serial_cmd("python3 -c 'import socket; serv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); cli = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); serv.bind(\"/tmp/test_sock\"); cli.connect(\"/tmp/test_sock\"); x = 10;cli.send(x.to_bytes(4, byteorder=\"little\")); x = serv.recv(32); print(x); cli.close(); serv.close()'"))
    #print(panda.run_serial_cmd("python3 scripts/cli_script.py"))
    panda.end_analysis()

    



panda.run()
