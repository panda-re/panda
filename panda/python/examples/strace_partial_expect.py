#!/usr/bin/env python3

# Run strace in the guest and on every syscall use consume_partial()
# to map syscall numbers to syscall names. This is a bit imprecise.
# Report results at the end

from pandare import Panda
panda = Panda(generic="x86_64")
target = "whoami"

last_enter_callno = None
results = {} # Callno: name(s)

@panda.queue_blocking
def run_cmds():
    panda.revert_sync("root")
    result = panda.run_serial_cmd("strace " + target)
    panda.end_analysis()

@panda.ppp("syscalls2", "on_all_sys_enter")
def all_sysenter(cpu, pc, callno):
    global last_enter_callno
    last_enter_callno = callno

@panda.ppp("syscalls2", "on_all_sys_return")
def all_sysret(cpu, pc, callno):
    proc = panda.plugins['osi'].get_current_process(cpu)
    if proc == panda.ffi.NULL or panda.ffi.string(proc.name).decode() != target:
        return

    strace_buffer = panda.serial_console.consume_partial()
    if not len(strace_buffer):
        return

    strace_results = strace_buffer.split("\n")
    cmds = [x.split("(")[0] for x in strace_results]

    if len(cmds) > 1:
        return # Unhandled - guest printed two results for one callback

    cname = cmds[0]
    if ")" in cname:
        return # Got some partial strace output

    if callno not in results:
        results[callno] = {} # name: count

    if cmds[0] not in results[callno]:
        results[callno][cname] = 1
    else:
        results[callno][cname] += 1



panda.run()

print()
print("#syscallno => name (times observed), alt-name (times observed)")
for callno, data in sorted(results.items()):
    out = ""
    for name, count in sorted(data.items(), key=lambda item: item[1], reverse=True):
        out += f"{name} ({count})\t"

    print(f"#{callno} =>\t {out}")
