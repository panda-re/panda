from pandare2 import Panda
from sys import argv

panda = Panda(generic="i386")

i = 0
d = {}

outfile = "out"

header = ["DRCOV VERSION: 2\n",
                "DRCOV FLAVOR: drcov-64\n",
                "Module Table: version 2, count 1\n",
                "Columns: id, base, end, entry, path\n"]

@panda.queue_blocking
def qb():
    from time import sleep
    sleep(10)
    panda.run_monitor_cmd("q")


def vcpu_tb_exec(cpu_index, udata):
    breakpoint()
    i = panda.ffi.cast("int", udata)
    d[i]['exec'] = True

@panda.cb_vcpu_tb_trans
def vcpu_tb(id, tb):
    breakpoint()
    # print(f"vcpu_tb in Python!!! {id} {tb}")
    pc = tb.vaddr
    
    global i
    d[i] = {'start': pc, 'mod_id': 0, 'exec': False, 'size': 0,
            'size': tb.size}
    
    # panda.cb_vcpu_tb_exec(vcpu_tb_exec, args=[tb, vcpu_tb_exec, panda.libpanda.QEMU_PLUGIN_CB_NO_REGS, panda.ffi.cast("void*", i)])
    panda.libpanda.qemu_plugin_register_vcpu_tb_exec_cb(tb.obj, vcpu_tb_exec, panda.libpanda.QEMU_PLUGIN_CB_NO_REGS, panda.ffi.cast("void*", i))
    i += 1

def atexit():
    print("at exit")
    with open(outfile,"wb") as f:
        path = panda.libpanda.qemu_plugin_path_to_binary()
        if path == panda.ffi.NULL:
            path = "?"
        start_code = panda.libpanda.qemu_plugin_start_code()
        end_code = panda.libpanda.qemu_plugin_end_code()
        entry = panda.libpanda.qemu_plugin_entry_code()
        for line in header:
            f.write(line.encode())
        f.write(f"0, {start_code:#x}, {end_code:#x}, {entry:#x}, {path}\n".encode())
        f.write(f"BB Table: {len(d)} entries\n".encode())
        from struct import pack
        for b in d:
            block = d[b]
            if block['exec']:
                outval = pack('I', block['start'])+pack('H', block['size'])+pack('H',block['mod_id'])
                f.write(outval)


print("entering main loop")
panda.run()
print("exiting")
atexit()