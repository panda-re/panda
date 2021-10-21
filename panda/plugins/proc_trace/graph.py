#!/usr/bin/env python3
'''
Create a graph of which processes run/ran over time.
Supports live systems or recordings

Example usage with a recording of the generic x86 qcow, run from the local directory:
    panda-system-x86_64 -m 1g -os linux-64-ubuntu:4.15.0-72-generic-noaslr-nokaslr -replay trace_test -panda snake_hook:files=graph.py
'''

class ProcGraph(PyPlugin):
    def __init__(self, panda):
        # Data collection
        self.procinfo = {} # PID: info
        self.time_data = [] # [(PID, #blocks)]
        self.total_insns = 0
        self.n_insns = 0
        self.last_pid = None

        # config options - TODO can we take these as an arg?
        self.n_cols = 120

        @panda.cb_before_block_exec
        def bbe(cpu, tb):
            self.n_insns += tb.icount
            self.total_insns += tb.icount

        @panda.ppp("osi", "on_task_change")
        def task_change(cpu):
            proc = panda.plugins['osi'].get_current_process(cpu)
            thread = panda.plugins['osi'].get_current_thread(cpu)

            if proc == panda.ffi.NULL:
                print(f"Warning: Unable to identify process at {self.n_insns}")
                return
            if thread == panda.ffi.NULL:
                print(f"Warning: Unable to identify thread at {self.n_insns}")
                return

            proc_key = (proc.pid, thread.tid)
            if proc_key not in self.procinfo:
                self.procinfo[proc_key] = {"names": set(), #"tids": set(),
                                      "first": self.total_insns, "last": None,
                                      "count": 0}

            name = panda.ffi.string(proc.name)  if proc.name != panda.ffi.NULL else "(error)"
            self.procinfo[proc_key]["names"].add(name)

            # Update insn count for last process and indicate it (maybe) ends at total_insns-1
            if self.last_pid:
                # count since we last ran is it's old end value, minus where it just ended
                self.procinfo[self.last_pid]["count"] += (self.total_insns-1) - self.procinfo[self.last_pid]["last"]  \
                                                if self.procinfo[self.last_pid]["last"] is not None \
                                                else (self.total_insns-1) - self.procinfo[self.last_pid]["first"]
                self.procinfo[self.last_pid]["last"] = self.total_insns-1

            self.last_pid = proc_key

            self.time_data.append((proc_key, self.n_insns))
            self.n_insns = 0

    def __del__(self):
        col_size = self.total_insns / self.n_cols
        pids = set([x for x,y in self.time_data]) # really a list of (pid, tid) tuples
        merged = {} # pid: [(True, 100), False, 9999)

        for pid in pids:
            on_off_times = []

            off_count = 0

            for (pid2, block_c) in self.time_data:
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

        for (pid, tid) in sorted(self.procinfo, key=lambda v: self.procinfo[v]['count'], reverse=True):
            details = self.procinfo[(pid, tid)]
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

            for cur_col in range(self.n_cols):
                counted = 0
                on_count = 0
                off_count = 0
                import ipdb
                while (counted < col_size and len(queue)): #or pending is not None:
                    if pending is not None:
                        (on_bool, cnt) = pending
                        pending = None
                    else:
                        old_len = len(queue)
                        (on_bool, cnt) = queue.pop(0)
                        assert(len(queue) < old_len), "pop don't happen"

                    if cnt > col_size-counted: #Hard case: count part, move remainder to pending
                        remainder = cnt - (col_size-counted)
                        cnt = col_size-counted # Maximum allowed now
                        pending = (on_bool, remainder)

                    assert(cnt <= col_size-counted) # Now it's (always) the easy case for what's left
                    if on_bool:
                        on_count += cnt
                    else:
                        off_count += cnt
                    counted += cnt

                # /while
                # Use on_count and off_count to determine how to label this cell
                density_map = " ▂▃▄▅▆▇"
                on_count / col_size

                idx = round((on_count/col_size)*(len(density_map)-1))
                c = density_map[idx]
                row += c

            ascii_art[(pid, tid)] = row

        # Render art
        print("PID  TID  | "+ "-"*(self.n_cols//2-4) + "HISTORY" + "-"*(self.n_cols//2-4) + "| NAMES")
        for (pid, tid) in sorted(ascii_art, key=lambda x: x[0]):
            row = ascii_art[(pid, tid)]
            details = self.procinfo[(pid, tid)]
            names = ", ".join([x.decode() for x in details['names']])
            print(f"{pid: <4} {tid: <4} |{row}| {names}")
