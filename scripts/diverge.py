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

def rr_driver_thread(command, logfile, work, results):
    process = pexpect.spawn(command, timeout=5)
    process.logfile = open(logfile, "w")
    process.expect_exact("(rr) ")

    while True:
        item, timeout = work.get()
        process.sendline(item)

        if item == "quit": break

        try:
            process.expect_exact("(rr) ", timeout=timeout)
        except pexpect.TIMEOUT:
            print process.before

        #print process.before + "(rr)",
        results.put(process.before)

class RRInstance(object):
    def __init__(self, replay, logfile):
        self.work = Queue()
        self.results = Queue()
        self.process = Process(target=rr_driver_thread, args=(
            "{} replay {}".format(rr_bin, replay),
            "record_log.txt",
            self.work,
            self.results
        ))

    def start(self):
        self.process.start()

record = RRInstance(record_rr, "record_log.txt")
record.start()
replay = RRInstance(replay_rr, "replay_log.txt")
replay.start()

other = { record: replay, replay: record }

def gdb_run(proc, cmd, timeout=-1):
    proc.work.put((cmd, timeout))
    proc.results.get()
    return proc.before

def gdb_run_both(cmd, timeout=-1):
    record.work.put((cmd, timeout))
    replay.work.put((cmd, timeout))

    record_str = None
    replay_str = None
    while not record_str and not replay_str:
        try:
            if not record_str:
                record_str = record.results.get(timeout=0.1)
            if not replay_str:
                replay_str = replay.results.get(timeout=0.1)
        except Queue_Empty: pass

    return {record: record_str, replay: replay_str}

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
gdb_run(record, "run {}".format(record_last))
gdb_run(replay, "run {}".format(replay_last))

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
    print_result(instr_counts)

    if instr_counts[record] == instr_counts[replay]:
        return False

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
        if ahead_event_low == ahead_event_high:
            raise Exception()

    return True

disable_all()
record_event_low = minimum_events[record]
record_event_high = maximum_events[record]
while record_event_low < record_event_high:
    mid = (record_event_low + record_event_high) / 2
    gdb_run()
    while back_up():
        pass

    checksums = get_checksums()
    if checksums[record] == checksums[replay]: # before divergence
        record_event_low = mid
    else:
        record_event_high = mid


record.interact()

#record.sendline("run {}".format(record_last))
#replay.sendline("run {}".format(replay_last))
#record.expect_exact("(rr)")
#replay.expect_exact("(rr)")
