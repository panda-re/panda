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
                print "EXCEPTION!"
                process.interact()

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
        print "(rr-{}) {}".format(descriptions[proc], cmds[proc])
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

def get_instr_count(proc):
    return get_instr_counts([proc])[proc]

def get_checksums(procs=[record, replay]):
    gdb_run_both("thread 3")
    return get_value(procs, "rr_checksum_memory()")

instr_count_max = get_instr_count(replay)
print "Failing replay instr count: {}", instr_count_max

def sync(instr_low, instr_high, target):
    instr_counts = get_instr_counts()
    print instr_counts

    if instr_counts[record] == instr_counts[replay]:
        return instr_counts[record]

    whens = get_whens()
    target_event_low = minimum_events[target]
    target_event_high = maximum_events[target]
    static = other[target]
    print "Syncing {} @ {} to match {} @ {}".format(
        target, instr_counts[target], static, instr_counts[static]
    )

    print "Event binary search."

    # Goal for first loop is to move target-session as close to static-session
    # as possible. Event-jumping is pretty fast.
    while target_event_low < target_event_high and \
            abs(instr_counts[record] - instr_counts[replay]) >= 10000:
        print "Bounds: [{}, {}]".format(target_event_low, target_event_high)
        mid = (target_event_low + target_event_high) / 2

        gdb_run(target, "run {}".format(mid), timeout=None)
        instr_counts = get_instr_counts()
        print instr_counts
        if instr_counts[target] < instr_counts[static]:
            # gone too far. go forward
            target_event_low = mid + 1
        elif instr_counts[target] > instr_counts[static]:
            target_event_high = mid - 1
        else:
            return instr_counts[target]

    if target_event_low == target_event_high:
        gdb_run(target, "run {}".format(target_event_low), timeout=None)

    # Now we do a slower synchronization. Optimally, run behind forward until it matches ahead.
    disable_all()
    enable("cpu_tb_exec")
    instr_counts = get_instr_counts()

    ahead = argmax(instr_counts)
    behind = other[ahead]
    BACKWARD = 0
    FORWARD = 1
    if instr_counts[ahead] >= instr_high - 10000:
        direction = BACKWARD
    else:
        direction = FORWARD
    while instr_counts[record] != instr_counts[replay]:
        assert instr_counts[behind] <= instr_high
        assert instr_counts[ahead] >= instr_low

        ahead = argmax(instr_counts)
        behind = other[ahead]
        print "Close. Doing slow sync up on {} @ {} behind {} @ {}".format(
            behind, instr_counts[behind], ahead, instr_counts[ahead]
        )

        # If our ahead guy is too far ahead, gotta bring it back.
        if direction == BACKWARD:
            condition("cpu_tb_exec", "cpus->tqh_first->rr_guest_instr_count <= {}"
                      .format(instr_counts[behind]))
            while get_instr_count(ahead) == instr_counts[ahead]:
                print "Rewinding {}".format(ahead)
                gdb_run(ahead, "reverse-continue", timeout=None)
        elif direction == FORWARD:
            condition("cpu_tb_exec", "cpus->tqh_first->rr_guest_instr_count >= {}"
                      .format(instr_counts[ahead]))
            while get_instr_count(behind) == instr_counts[behind]:
                print "Advancing {}".format(behind)
                gdb_run(behind, "continue", timeout=None)
        else: assert False
        instr_counts = get_instr_counts()

    return instr_counts[record]

sync(0, instr_count_max, record)

maximum_events = get_whens()

disable_all()
replay_event_low = minimum_events[replay]
replay_event_high = maximum_events[replay]
record_event_low = minimum_events[record]
record_event_high = maximum_events[record]
max_converged_instr = 0
min_diverged_instr = instr_count_max
divergence_info = """
-----------------------------------------------------
Current divergence understanding:
    Instr range: [{instr_lo}, {instr_hi}]
    Record event range: [{record_lo}, {record_hi}]
    Replay event range: [{replay_lo}, {replay_hi}]
------------------------------------------------------
"""

while replay_event_low < replay_event_high:
    mid = (replay_event_low + replay_event_high) / 2

    print "Moving replay to event {} to find divergence".format(mid)
    gdb_run(replay, "run {}".format(mid))

    now_instr = sync(0, instr_count_max, record)
    whens = get_whens()

    checksums = get_checksums()

    print
    print "Current checksums:", checksums
    if checksums[replay] != checksums[record]: # after divergence
        min_diverged_instr = min(min_diverged_instr, now_instr)
        record_event_high = min(record_event_high, whens[record])
        replay_event_high = whens[replay] - 1 # we're looking too late, go back
    else:
        max_converged_instr = max(max_converged_instr, now_instr)
        record_event_low = max(record_event_low, whens[record])
        replay_event_low = whens[replay] # look forwards

    print divergence_info.format(
        instr_lo=max_converged_instr,
        instr_hi=min_diverged_instr,
        record_lo=record_event_low,
        record_hi=record_event_high,
        replay_lo=replay_event_low,
        replay_hi=replay_event_high,
    )
