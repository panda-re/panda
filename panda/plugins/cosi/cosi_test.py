from pandare import Panda, PyPlugin
import argparse

parser = argparse.ArgumentParser(
    prog = "CosiTester",
    description = "Check if different parts of Cosi match old OSI view"
)

parser.add_argument('-p', '--proc', action='store_true', help="Check view of task_struct")
parser.add_argument('-t', '--thread', action='store_true', help="Check view of thread")
parser.add_argument('-f', '--file',  action='store_true', help="Check view of files")
parser.add_argument('-m', '--module',  action='store_true', help="Check view of modules")
parser.add_argument('-s', '--symbols', default="default", help="Path to the Vol3 symbol table you want to use. Should be a .json.xz file. Default helps only Ryan.")
parser.add_argument('-l', '--list', action='store_true', help="Check view of process list")

args = parser.parse_args()

def get_proc_info(cpu, current):
    #print(f"{current=} | {dir(current)}")
    if current.name != panda.ffi.NULL:
        name = panda.ffi.string(current.name).decode('utf-8', errors='ignore')
    else:
        name = "ERROR"
    print(f"{current.asid=:x} | {current.create_time=:x} | {name=} | {current.pages=} | {current.pid=} | {current.ppid=} | {current.taskd=:x}")

def get_thread_info(cpu):
    current_thread = panda.plugins['osi'].get_current_thread(cpu)
    print(f"{current_thread.pid=:x} | {current_thread.tid=:x}")

def get_file_info(cpu, current):
    MAX_FD_LIM = 256
    for i in range(0, MAX_FD_LIM):
        fname = panda.plugins["osi_linux"].osi_linux_fd_to_filename(cpu, current, i)
        if fname:
            if res_name := panda.ffi.string(fname).decode('utf-8', errors='ignore'):
                if res_name != panda.ffi.NULL:
                    print(f"{i=} | {res_name=}")
                else:
                    break
            else:
                break
        else:
            break

def get_module_info(cpu, current):
    for mapping in panda.get_mappings(cpu):
        if mapping.file != panda.ffi.NULL:
            file = panda.ffi.string(mapping.file).decode()
        else:
            file = "[unknown]"
        if mapping.name != panda.ffi.NULL:
            name = panda.ffi.string(mapping.name).decode()
        else:
            name = "[unknown]"
        print(f"{mapping.modd=:x} | {mapping.base=:x} | {mapping.size=:x} | {file=} | {name=}")

def get_processlist_info(cpu):
    ps = panda.get_processes(cpu)
    first = True
    for p in ps:
        #get_proc_info(cpu, p)
        if first:
            print("Init proc")
            first = False
        if p.name != panda.ffi.NULL:
            name = panda.ffi.string(p.name).decode('utf-8', errors='ignore')
        else:
            name = "ERROR"
        print(f"proc_name: {name} | pid: {p.pid} | ppid: {p.ppid}")

panda = Panda(generic='x86_64')
@panda.queue_blocking
def driver():
    panda.revert_sync('root')
    if args.symbols == "default":
        prof_file = "ubuntu:4.15.0-72-generic:64"
    else:
        prof_file = args.symbols
    
    panda.load_plugin("cosi", args = {"profile": prof_file})
    #panda.load_plugin("cosi")
    panda.load_plugin("osi")
    panda.load_plugin("osi_linux")

    #@panda.ppp("osi", "on_asid_change")
    @panda.cb_asid_changed()
    def on_task_change(cpu, old, new):
        print(f"\nOSI CLASSIC INFO START")
        current = panda.plugins['osi'].get_current_process(cpu)
        if args.proc:
            get_proc_info(cpu, current)
        if args.thread:
            get_thread_info(cpu)
        if args.file:
            get_file_info(cpu, current)
        if args.module:
            get_module_info(cpu, current)
        if args.list:
            get_processlist_info(cpu)
        print(f"OSI CLASSIC INFO END\n")
        return 1

    print(panda.run_serial_cmd("cat /proc/version | grep 'test'"))
    panda.end_analysis()

panda.run()
