#!/usr/bin/env python3
'''
Generate a recording if one does not exist, then use the on_task_change
callback to collect information about when various processes are running.

Also load asidstory plugin to compare output.
'''
from pandare import Panda

panda = Panda(generic="x86_64")

# If no recording exists, generate one
rec_name = "trace_test"
if not panda.recording_exists(rec_name):
    @panda.queue_blocking
    def drive():
        panda.record_cmd("find /tmp | md5sum", recording_name=rec_name)
        panda.end_analysis()
    panda.run()


# Data collection
procinfo = {} # PID: info
time_data = [] # [(PID, #blocks)]
total_insns = 0
n_insns = 0
last_pid = None

@panda.cb_before_block_exec
def bbe(cpu, tb):
    global n_insns, total_insns
    n_insns += tb.icount
    total_insns += tb.icount

@panda.ppp("osi", "on_task_change")
def task_change(cpu):
    proc = panda.plugins['osi'].get_current_process(cpu)
    thread = panda.plugins['osi'].get_current_thread(cpu)

    global n_insns
    if proc == panda.ffi.NULL:
        print(f"Warning: Unable to identify process at {n_insns}")
        return
    if thread == panda.ffi.NULL:
        print(f"Warning: Unable to identify thread at {n_insns}")
        return

    proc_key = (proc.pid, thread.tid)
    if proc_key not in procinfo:
        procinfo[proc_key] = {"names": set(), #"tids": set(),
                              "first": total_insns, "last": None,
                              "count": 0}

    name = panda.ffi.string(proc.name)  if proc.name != panda.ffi.NULL else "(error)"
    procinfo[proc_key]["names"].add(name)
    #procinfo[proc_key]["tids"].add(thread.tid)

    # Update insn count for last process and indicate it (maybe) ends at total_insns-1
    global last_pid
    if last_pid:
        # count since we last ran is it's old end value, minus where it just ended
        procinfo[last_pid]["count"] += (total_insns-1) - procinfo[last_pid]["last"]  \
                                        if procinfo[last_pid]["last"] is not None \
                                        else (total_insns-1) - procinfo[last_pid]["first"]
        procinfo[last_pid]["last"] = total_insns-1

    last_pid = proc_key

    time_data.append((proc_key, n_insns))
    n_insns = 0

# For testing: compare to asidstory
panda.load_plugin("asidstory", {"width": 120})
panda.run_replay(rec_name)

# config
n_cols = 120

# Analyze data
col_size = total_insns / n_cols
pids = set([x for x,y in time_data]) # really a list of (pid, tid) tuples
merged = {} # pid: [(True, 100), False, 9999)

for pid in pids:
    on_off_times = []

    off_count = 0

    for (pid2, block_c) in time_data:
        if pid2 == pid:
            # On!
            on_off_times.append((True, block_c))
        else:
            # Off
            on_off_times.append((False, block_c))

    merged[pid] = on_off_times

# Render output: Stage 1 - PID -> procname details
#   Count   Pid              Name/tid              Asid    First         Last
#    297  1355   [bash find  / 1355]          3b14e000   963083  ->  7829616

print(" Ins.Count PID   TID  First       Last     Names")

for (pid, tid) in sorted(procinfo, key=lambda v: procinfo[v]['count'], reverse=True):
    details = procinfo[(pid, tid)]
    names = ", ".join([x.decode() for x in details['names']])
    print(f"{details['count']: >10} {pid:<5} {tid:<5}{details['first']:<8} -> {details['last']:<8} {names}")


# Render output: Stage 2: ascii art
ascii_art = {} # (pid, tid): art
for (pid, tid), times in merged.items():
    row = ""
    pending = None
    queue = merged[(pid, tid)]
    # Consume data from pending+merged in chunks of col_size
    # e.g. col_size=10 (True, 8), (False, 1), (True, 10)
    # simplifies to {True:9, False:1} and adds (True:9) to pending

    for cur_col in range(n_cols):
        counted = 0
        on_count = 0
        off_count = 0
        import ipdb
        while (counted < col_size and len(queue)): #or pending is not None:
            #print(f"Cell {cur_col}: Counted {counted} of {col_size} with {len(queue)} remaining. Pending is none: {pending is None}")
            #ipdb.set_trace()
            if pending is not None:
                # Pull from pending
                #print("Pending POP:", on_bool, cnt)
                (on_bool, cnt) = pending
                pending = None
            else:
                old_len = len(queue)
                (on_bool, cnt) = queue.pop(0)
                #print("Queue POP:", on_bool, cnt)
                assert(len(queue) < old_len), "pop don't happen"

            if cnt > col_size-counted: #Hard case: count part, move remainder to pending
                remainder = cnt - (col_size-counted)
                cnt = col_size-counted # Maximum allowed now
                #print("Set pending with remainder {remainder}")

                pending = (on_bool, remainder)

            assert(cnt <= col_size-counted) # Now it's (always) the easy case for what's left
            if on_bool:
                on_count += cnt
            else:
                off_count += cnt
            counted += cnt


        # /while
        # Use on_count and off_count to determine how to label this cell

        #□▢▭▯▤▥▦▧▨▩▫▣▪▬▮■
        #" □◍▲◕■"
        #density_map = " ◌○◔◒◕●"
        density_map = " ▂▃▄▅▆▇"
                #      01234567
        on_count / col_size

        idx = round((on_count/col_size)*(len(density_map)-1))
        c = density_map[idx]
        row += c

    ascii_art[(pid, tid)] = row

# Render art
print("PID  TID  | "+ "-"*(n_cols//2-4) + "HISTORY" + "-"*(n_cols//2-4) + "| NAMES")
for (pid, tid) in sorted(ascii_art, key=lambda x: x[0]):
    row = ascii_art[(pid, tid)]
    details = procinfo[(pid, tid)]
    names = ", ".join([x.decode() for x in details['names']])
    print(f"{pid: <4} {tid: <4} |{row}| {names}")
