#!/usr/bin/python

import pexpect
import os
import sys
import re
import operator
from subprocess32 import check_output
from multiprocessing import Process, Queue
from Queue import Empty as Queue_Empty

def argmax(d):
    return max(d.iteritems(), key=operator.itemgetter(1))[0]
def argmin(d):
    return min(d.iteritems(), key=operator.itemgetter(1))[0]

rr_bin = "/home/moyix/git/rr/build/bin/rr"

if len(sys.argv) != 3:
    print "diverge.py record replay"

def get_last_event(replay):
    cmd = ("{} dump {} | grep global_time | tail -n 1 | " + \
        "sed -E 's/^.*global_time:([0-9]+),.*$/\\1/'").format(rr_bin, replay)

    print cmd
    str_result = check_output(cmd, shell=True)
    return int(str_result)

record_rr = sys.argv[1]
replay_rr = sys.argv[2]

record_last = 1153018 #get_last_event(record_rr)
replay_last = 25326 #get_last_event(replay_rr)

print record_last, replay_last


class RRInstance(Process):
    def __init__(self, description, replay, logfile, results_queue):
        self.description = description
        self.work = Queue()
        self.results_queue = results_queue
        self.spawn_cmd = "{} replay {}".format(rr_bin, replay)
        self.logfile = logfile

        Process.__init__(self)

    def __repr__(self):
        return "RRInstance({!r})".format(self.description)

    def run(self):
        process = pexpect.spawn(self.spawn_cmd, timeout=5)
        process.logfile = open(self.logfile, "w")
        process.expect_exact("(rr) ")

        while True:
            item, timeout = self.work.get()
            process.sendline(item)

            if item == "quit": break

            try:
                process.expect_exact("(rr) ", timeout=timeout)
            except pexpect.TIMEOUT:
                print process.before
                raise

            #print process.before + "(rr)",
            self.results_queue.put((self.description, process.before))

results_queue = Queue()
record = RRInstance("record", record_rr, "record_log.txt", results_queue)
record.start()
replay = RRInstance("replay", replay_rr, "replay_log.txt", results_queue)
replay.start()

other = { record: replay, replay: record }
descriptions = { record: "record", replay: "replay" }
objs = { "record": record, "replay": replay }

def gdb_run(proc, cmd, timeout=-1):
    print "(rr-{}) {}".format(descriptions[proc], cmd)
    proc.work.put((cmd, timeout))
    return results_queue.get()[1]

def gdb_run_both(cmd, timeout=-1):
    if isinstance(cmd, str):
        cmds = { record: cmd, replay: cmd }
    elif isinstance(cmd, dict):
        cmds = cmd
    else:
        assert False

    for proc in cmds:
        proc.work.put((cmds[proc], timeout))

    results = {}
    for i in range(2):
        name, value = results_queue.get()
        results[objs[name]] = value

    return results

replay.logfile = open("replay_log.txt", "w")

gdb_run_both("set confirm off")

breakpoints = {}
def breakpoint(break_arg):
    result = gdb_run_both("break {}".format(break_arg))[record]
    bp_num = int(re.search(r"Breakpoint ([0-9]+) at", result).group(1))
    breakpoints[break_arg] = bp_num

def disable_all():
    gdb_run_both("disable")

def enable(break_arg):
    gdb_run_both("enable {}".format(breakpoints[break_arg]))

def condition(break_arg, cond):
    gdb_run_both("condition {} {}".format(breakpoints[break_arg], cond))

breakpoint("rr_do_begin_record")
breakpoint("rr_do_begin_replay")
gdb_run_both("continue", timeout=120)
gdb_run_both("finish", timeout=10)

def get_whens():
    result = gdb_run_both("when")
    return { k: int(re.search(r"Current event: ([0-9]+)", v).group(1)) for k, v in result.items()}

minimum_events = get_whens()
maximum_events = { record: record_last, replay: replay_last }

# get last instruction in failed replay
gdb_run_both({
    record: "run {}".format(record_last),
    replay: "run {}".format(replay_last)
}, timeout=120)

breakpoint("cpu_tb_exec")
gdb_run_both("reverse-continue")

def print_result(result):
    print "{{ record: {!r}, replay: {!r} }}".format(result[record], result[replay])

def get_value(procs, value_str):
    result = { proc: gdb_run(proc, "print {}".format(value_str)) \
              for proc in procs }
    return { k: int(re.search(r"\$[0-9]+ = ([0-9]+)", v).group(1)) for k, v in result.items()}

def get_instr_counts(procs=[record, replay]):
    return get_value(procs, "cpus->tqh_first->rr_guest_instr_count")

def get_checksums(procs=[record, replay]):
    return get_value(procs, "rr_checksum_memory()")

def back_up():
    instr_counts = get_instr_counts()
    print instr_counts

    if instr_counts[record] == instr_counts[replay]:
        return instr_counts[record]

    ahead = argmax(instr_counts)
    behind = other[ahead]

    if abs(instr_counts[record] - instr_counts[replay]) < 100000:
        disable_all()
        enable("cpu_tb_exec")
        condition("cpu_tb_exec", "cpus->tqh_first->rr_guest_instr_count <= {}"
                .format(instr_counts[behind]))
        gdb_run(ahead, "reverse-continue", timeout=None)
    else:
        whens = get_whens()
        ahead_event_low = minimum_events[ahead]
        ahead_event_high = whens[ahead]
        while ahead_event_low < ahead_event_high and \
                abs(instr_counts[record] - instr_counts[replay]) >= 100000:
            mid = (ahead_event_low + ahead_event_high) / 2
            gdb_run(ahead, "run {}".format(mid), timeout=None)
            if get_instr_counts([ahead]) < instr_counts[behind]:
                # gone too far. go forward
                ahead_event_low = mid
            else:
                ahead_event_high = mid
        if ahead_event_low >= ahead_event_high:
            raise Exception()

    return None

while not back_up(): pass
maximum_events = get_instr_counts()

disable_all()
record_event_low = minimum_events[record]
record_event_high = maximum_events[record]
while record_event_low < record_event_high:
    mid = (record_event_low + record_event_high) / 2
    gdb_run(record, "run {}".format(mid))

    now = None
    while not now:
        now = back_up()

    checksums = get_checksums()
    if checksums[record] != checksums[replay]: # after divergence
        record_event_high = now
    else:
        record_event_low = now

record.interact()

#record.sendline("run {}".format(record_last))
#replay.sendline("run {}".format(replay_last))
#record.expect_exact("(rr)")
#replay.expect_exact("(rr)")
