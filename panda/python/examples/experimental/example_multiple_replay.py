from pandare import Panda

panda = Panda(generic="i386")

from os.path import exists

if not exists("cool_recording-rr-snp"):
    @panda.queue_blocking
    def do_stuff():
        panda.revert_sync("root")
        print(panda.run_serial_cmd("echo abcdefgh | tee cool_file"))
        panda.run_monitor_cmd("begin_record cool_recording")
        print(panda.run_serial_cmd("cat cool_file | nc 18.4.83.213 8888"))
        panda.run_monitor_cmd("end_record")
        panda.end_analysis()

    panda.run()
print("done with iniital section")
## print out all the files we saw
#@panda.ppp("syscalls2","on_sys_open_return")
#def sys_open_return(cpu, pc, path, flags,mode):
#    print(f"File opened {panda.read_str(cpu,path)}")
#
#@panda.cb_asid_changed
#def asid_changed(cpu, old,new):
#    print(f"new_asid {cpu.rr_guest_instr_count}")
#    return 0
#    
#panda.run_replay("cool_recording")
#
## print out all the files we saw
#@panda.ppp("syscalls2","on_sys_open_return")
#def sys_open_return(cpu, pc, path, flags,mode):
#    print(f"File opened second time {panda.read_str(cpu,path)}")
#
#@panda.cb_asid_changed
#def asid_changed(cpu, old,new):
#    print(f"new_asid {cpu.rr_guest_instr_count}")
#    return 0
#    
#panda.run_replay("cool_recording")

for i in range(10):

    @panda.cb_asid_changed
    def asid_changed(cpu, old,new):
        print(f"new_asid {cpu.rr_guest_instr_count}")
        return 0

    panda.run_replay("cool_recording")

