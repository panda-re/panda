#!/usr/bin/python
import IPython
import argparse
import pexpect
import os
import re
import operator
from subprocess32 import check_output
from multiprocessing import Process, Queue

def get_default_rr_path():
    try:
        rr_path = check_output(["which", "rr"]).strip()
    except:
        rr_path = None
    return rr_path

default_rr = get_default_rr_path()
parser = argparse.ArgumentParser(description="A script to automatically find replay divergences")
parser.add_argument("record_rr", help="Path to the rr directory for the recording replay")
parser.add_argument("replay_rr", help="Path to the rr directory for the replay replay")
parser.add_argument("--rr", default=default_rr,
                    help="A path to the rr binary (default={})".format(default_rr))
parser.add_argument("--record-event-bounds",
                    help="Event bounds for record to seed search, comma-separated.")
parser.add_argument("--replay-event-bounds",
                    help="Event bounds for replay to seed search, comma-separated.")
parser.add_argument("--instr-bounds",
                    help=("Instruction bounds where divergence could have occurred.\n" + \
                          "Also to seed search."))
parser.add_argument("--instr-max", help="Last instruction before replay failed.")
args = parser.parse_args()

# Check arguments
if not os.path.isfile(args.rr):
    raise IOError("Cannot find rr bin at {}".format(args.rr))
if not os.path.isdir(args.record_rr):
    raise IOError("Cannot find recording replay at {}".format(args.record_rr))
if not os.path.isdir(args.replay_rr):
    raise IOError("Cannot find replay replay at {}".format(args.replay_rr))

def argmax(d):
    return max(d.iteritems(), key=operator.itemgetter(1))[0]
def argmin(d):
    return min(d.iteritems(), key=operator.itemgetter(1))[0]

assert args.rr

class RRInstance(Process):
    def __init__(self, description, rr_replay, logfile, results_queue):
        self.description = description
        self.work = Queue()
        self.results_queue = results_queue
        self.spawn_cmd = "{} replay {}".format(args.rr, rr_replay)
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

            if item == "quit":
                self.results_queue.put((self.description, "quit"))
                break

            try:
                process.expect_exact("(rr) ", timeout=timeout)
            except pexpect.TIMEOUT:
                print process.before
                print "EXCEPTION!"
                IPython.embed()

            self.results_queue.put((self.description, process.before))

        process.terminate()

results_queue = Queue()
record = RRInstance("record", args.record_rr, "record_log.txt", results_queue)
record.start()
replay = RRInstance("replay", args.replay_rr, "replay_log.txt", results_queue)
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
    if isinstance(cond, str):
        conds = { record: cond, replay: cond }
    elif isinstance(cond, dict):
        conds = cond
    else: assert False

    gdb_run_both({
        record: "condition {} {}".format(breakpoints[break_arg], conds[record]),
        replay: "condition {} {}".format(breakpoints[break_arg], conds[replay])
    })

gdb_run_both("set confirm off")
gdb_run_both("set pagination off")

breakpoint("rr_do_begin_record")
breakpoint("rr_do_begin_replay")
gdb_run_both("continue", timeout=None)
gdb_run_both("finish", timeout=None)
gdb_run_both("watch cpus->tqh_first->rr_guest_instr_count")
gdb_run_both("continue", timeout=None)

breakpoint("cpu_tb_exec")

def get_whens():
    result = gdb_run_both("when")
    return { k: int(re.search(r"Current event: ([0-9]+)", v).group(1)) for k, v in result.items()}

def get_value(procs, value_str):
    if set(procs) != set([record, replay]):
        result = { proc: gdb_run(proc, "print {}".format(value_str)) \
                for proc in procs }
    else:
        result = gdb_run_both("print {}".format(value_str))
    return { k: int(re.search(r"\$[0-9]+ = ([0-9]+)", v).group(1)) for k, v in result.items()}

def get_instr_counts(procs=[record, replay]):
    return get_value(procs, "cpus->tqh_first->rr_guest_instr_count")

def get_instr_count(proc):
    return get_instr_counts([proc])[proc]

def get_checksums(procs=[record, replay]):
    # NB: Only run when you are at a breakpoint in CPU thread!
    gdb_run_both("info threads")
    result = gdb_run_both("print rr_checksum_memory()")
    for proc, result_str in result.items():
        assert "Need to be in VCPU" not in result_str
    return { k: int(re.search(r"\$[0-9]+ = ([0-9]+)", v).group(1)) for k, v in result.items()}

def get_last_event(replay_dir):
    cmd = ("{} dump {} | grep global_time | tail -n 1 | " + \
        "sed -E 's/^.*global_time:([0-9]+),.*$/\\1/'").format(args.rr, replay_dir)

    str_result = check_output(cmd, shell=True)
    return int(str_result)

record_last = get_last_event(args.record_rr)
replay_last = get_last_event(args.replay_rr)

print "Last known events: record={}, replay={}".format(record_last, replay_last)

if args.record_event_bounds and args.replay_event_bounds and args.instr_bounds:
    record_bounds = map(int, args.record_event_bounds.split(','))
    replay_bounds = map(int, args.replay_event_bounds.split(','))
    minimum_events = { record: record_bounds[0], replay: replay_bounds[0] }
    maximum_events = { record: record_bounds[1], replay: replay_bounds[1] }

    if args.instr_max:
        instr_count_max = int(args.instr_max)
    else:
        gdb_run(replay, "run {}".format(replay_last), timeout=None)
        gdb_run(replay, "reverse-continue", timeout=None)
        instr_count_max = get_instr_count(replay)

    gdb_run_both({
        record: "run {}".format(maximum_events[record]),
        replay: "run {}".format(maximum_events[replay])
    }, timeout=None)

    gdb_run_both("reverse-continue", timeout=None)

else:
    minimum_events = { k: v + 1 for k, v in get_whens().items() }
    maximum_events = { record: record_last, replay: replay_last }

    # get last instruction in failed replay
    gdb_run_both({
        record: "run {}".format(record_last),
        replay: "run {}".format(replay_last)
    }, timeout=None)

    gdb_run_both("reverse-continue", timeout=None)

    instr_count_max = get_instr_count(replay)
    print "Failing replay instr count:", instr_count_max

def sync(instr_low, instr_high, target):
    instr_counts = get_instr_counts()
    print instr_counts

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

    if target_event_low == target_event_high:
        gdb_run(target, "run {}".format(target_event_low), timeout=None)

    # Now we do a slower synchronization. Optimally, run behind forward until it matches ahead.
    disable_all()
    enable("cpu_tb_exec")
    condition("cpu_tb_exec", "")
    gdb_run_both("reverse-continue", timeout=None)
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
            print "Rewinding {}".format(ahead)
            condition("cpu_tb_exec", {
                behind: "",
                ahead: "cpus->tqh_first->rr_guest_instr_count <= {}"
                      .format(instr_counts[behind])
            })
            if "cpu_loop_exec_tb" not in gdb_run(behind, "backtrace"):
                gdb_run_both("reverse-continue", timeout=None)
            while get_instr_count(ahead) == instr_counts[ahead]:
                gdb_run(ahead, "reverse-continue", timeout=None)
        elif direction == FORWARD:
            print "Advancing {}".format(behind)
            condition("cpu_tb_exec", {
                ahead: "",
                behind: "cpus->tqh_first->rr_guest_instr_count >= {}"
                      .format(instr_counts[ahead])
            })
            if "cpu_loop_exec_tb" not in gdb_run(ahead, "backtrace"):
                gdb_run_both("continue", timeout=None)
            while get_instr_count(behind) == instr_counts[behind]:
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

if args.instr_bounds:
    instr_bounds = map(int, args.instr_bounds.split(','))
    max_converged_instr = instr_bounds[0]
    min_diverged_instr = instr_bounds[1]
else:
    max_converged_instr = 0
    min_diverged_instr = instr_count_max

divergence_info = """
-----------------------------------------------------
Current divergence understanding:
    Instr range: [{instr_lo}, {instr_hi}]
    Record event range: [{record_lo}, {record_hi}]
    Replay event range: [{replay_lo}, {replay_hi}]

    Args to get back here:
    --record-event-bounds={record_lo},{record_hi} \\
    --replay-event-bounds={replay_lo},{replay_hi} \\
    --instr-bounds={instr_lo},{instr_hi} \\
    --instr-max={instr_max}
------------------------------------------------------
"""

def print_divergence_info():
    print divergence_info.format(
        instr_lo=max_converged_instr,
        instr_hi=min_diverged_instr,
        record_lo=record_event_low,
        record_hi=record_event_high,
        replay_lo=replay_event_low,
        replay_hi=replay_event_high,
        instr_max=instr_count_max
    )

last_event_range = (0, 0)
whens = get_whens()
while last_event_range != (replay_event_low, replay_event_high):
    last_event_range = (replay_event_low, replay_event_high)
    print_divergence_info()

    mid = (replay_event_low + replay_event_high) / 2

    print "Moving replay to event {} to find divergence".format(mid)
    gdb_run(replay, "run {}".format(mid), timeout=None)

    now_instr = sync(0, instr_count_max, record)
    whens = get_whens()

    checksums = get_checksums()

    print
    print whens
    print "Current checksums:", checksums
    if checksums[replay] != checksums[record]: # after divergence
        min_diverged_instr = min(min_diverged_instr, now_instr)
        record_event_high = min(record_event_high, whens[record])
        replay_event_high = whens[replay] # we're looking too late, go back
    else:
        max_converged_instr = max(max_converged_instr, now_instr)
        record_event_low = max(record_event_low, whens[record])
        replay_event_low = whens[replay] # look forwards

print "Haven't made progress since last iteration. Moving to memory checksum."
print_divergence_info()

gdb_run_both({
    record: "run {}".format(record_event_high),
    replay: "run {}".format(replay_event_high),
}, timeout=None)
disable_all()
sync(0, instr_count_max, record)

ram_size = get_value([record], "ram_size")[record]

def get_crc32s(low, size):
    return get_value([record, replay],
                     "(uint32_t)crc32(0, $ptr + {}, {})".format(
                         hex(low), hex(size)))

gdb_run_both("set $ptr = memory_region_find(" + \
             "get_system_memory(), 0x2000000, 1).mr->ram_block.host")

search_queue = [(0, ram_size)]
divergences = []
while search_queue:
    low, high = search_queue.pop()
    if high - low <= 4:
        print "Divergence occurred in range [{:08x}, {:08x}]".format(
            low, high)
        divergences.append(low)
        continue

    size = (high - low) / 2
    crc32s_low = get_crc32s(low, size)
    crc32s_high = get_crc32s(low + size, size)

    if crc32s_low[record] != crc32s_low[replay]:
        search_queue.append((low, high - size))
    if crc32s_high[record] != crc32s_high[replay]:
        search_queue.append((low + size, high))

divergences.sort()
diverged_ranges = []
for d in divergences:
    if not diverged_ranges:
        diverged_ranges.append([d, d+4])
    elif diverged_ranges[-1][1] == d:
        diverged_ranges[-1][1] += 4
    else:
        diverged_ranges.append([d, d+4])

print divergences
print diverged_ranges

ram_ptrs = get_value([record, replay], "(uint64_t)memory_region_find(" + \
             "get_system_memory(), 0x2000000, 1).mr->ram_block.host")

gdb_run_both({
    record: "run {}".format(record_event_low),
    replay: "run {}".format(replay_event_low),
}, timeout=None)
disable_all()
sync(0, max_converged_instr, record)

disable_all()
if len(diverged_ranges) > 4:
    print "WARNING: Too much divergence! Trying anyway."
for d in diverged_ranges[-4:]:
    gdb_run_both({
        k: "watch *0x{:x}".format(ram_ptrs[k] + d[0]) for k in [record, replay]
    })

instr_counts = get_instr_counts()
while instr_counts[record] == instr_counts[replay] and \
        instr_counts[record] > 0:
    gdb_run_both("continue", timeout=None)
    instr_counts = get_instr_counts()

if instr_counts[record] > 0:
    backtraces = gdb_run_both("backtrace")

    print
    print "RECORD BACKTRACE: "
    print backtraces[record]
    print
    print "REPLAY BACKTRACE: "
    print backtraces[replay]
else:
    print
    print "Failed to find exact divergence. Look at mem ranges {}".format(
            diverged_ranges)
    print_divergence_info()

IPython.embed()

gdb_run_both("quit")

record.join()
replay.join()
