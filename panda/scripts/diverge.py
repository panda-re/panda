#!/usr/bin/python
import IPython
import argparse
import pexpect
import os
import re
import operator
from subprocess32 import check_output
from multiprocessing import Process, Queue
from blist import sorteddict

DEBUG_COUNTER_PERIOD = 1 << 17

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
parser.add_argument("--instr-bounds",
                    help=("Instruction bounds where divergence could have occurred.\n" + \
                          "Also to seed search."))
parser.add_argument("--instr-max", help="Last instruction before replay failed.")
cli_args = parser.parse_args()

# Check arguments
if not os.path.isfile(cli_args.rr):
    raise IOError("Cannot find rr bin at {}".format(cli_args.rr))
if not os.path.isdir(cli_args.record_rr):
    raise IOError("Cannot find recording replay at {}".format(cli_args.record_rr))
if not os.path.isdir(cli_args.replay_rr):
    raise IOError("Cannot find replay replay at {}".format(cli_args.replay_rr))

def argmax(d):
    return max(d.iteritems(), key=operator.itemgetter(1))[0]
def argmin(d):
    return min(d.iteritems(), key=operator.itemgetter(1))[0]

assert cli_args.rr

class RRInstance(Process):
    def __init__(self, description, rr_replay, logfile, results_queue, *args, **kwargs):
        self.description = description
        self.work = Queue()
        self.results_queue = results_queue
        self.spawn_cmd = "{} replay {}".format(cli_args.rr, rr_replay)
        self.logfile = logfile

        Process.__init__(self, *args, **kwargs)

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
record = RRInstance("record", cli_args.record_rr, "record_log.txt", results_queue)
record.start()
replay = RRInstance("replay", cli_args.replay_rr, "replay_log.txt", results_queue)
replay.start()

both = [record, replay]
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
    for i in range(len(cmds)):
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

def get_value(procs, value_str):
    if set(procs) != set([record, replay]):
        result = { proc: gdb_run(proc, "print/u {}".format(value_str)) \
                for proc in procs }
    else:
        result = gdb_run_both("print/u {}".format(value_str))
    return { k: int(re.search(r"\$[0-9]+ = ([0-9]+)", v).group(1)) for k, v in result.items()}

def get_same_value(value_str):
    return get_value([record], value_str)[record]

gdb_run_both("set confirm off")
gdb_run_both("set pagination off")

breakpoint("rr_do_begin_record")
breakpoint("rr_do_begin_replay")
gdb_run_both("continue", timeout=None)
ram_ptrs = get_value([record, replay], "memory_region_find(" + \
             "get_system_memory(), 0x2000000, 1).mr->ram_block.host")

gdb_run_both("finish", timeout=None)
gdb_run_both("watch cpus->tqh_first->rr_guest_instr_count")
gdb_run_both("continue", timeout=None)

breakpoint("cpu_loop_exec_tb")
breakpoint("debug_counter")

def get_whens():
    result = gdb_run_both("when")
    try:
        ret = { k: int(re.search(r"Current event: ([0-9]+)", v).group(1)) for k, v in result.items()}
    except AttributeError:
        ret = { record: 0, replay: 0 }
        IPython.embed()
    return ret

def get_instr_counts(procs=[record, replay]):
    return get_value(procs, "cpus->tqh_first->rr_guest_instr_count")

def get_instr_count(proc):
    return get_instr_counts([proc])[proc]

ram_size = get_same_value("ram_size")

def get_crc32s(low, size, procs=[record, replay]):
    step = 1 << 31 if size > (1 << 31) else size
    crc32s = { proc: 0 for proc in procs }
    for start in range(low, low + size, step):
        for proc in procs:
            crc32s[proc] ^= get_value([proc],
                        "(uint32_t)crc32(0, {} + {}, {})".format(
                            hex(ram_ptrs[proc]), hex(start), hex(step)))[proc]
    return crc32s

def get_checksums(procs=[record, replay]):
    # NB: Only run when you are at a breakpoint in CPU thread!
    gdb_run_both("info threads")
    memory = get_crc32s(0, ram_size, procs)
    regs = get_value(procs, "rr_checksum_regs()")
    return { k: (memory[k], regs[k]) for k in procs }

def checksums_equal():
    checksums = get_checksums()
    return checksums[record] == checksums[replay]

def get_last_event(replay_dir):
    cmd = ("{} dump {} | grep global_time | tail -n 1 | " + \
        "sed -E 's/^.*global_time:([0-9]+),.*$/\\1/'").format(cli_args.rr, replay_dir)

    str_result = check_output(cmd, shell=True)
    return int(str_result)

record_last = get_last_event(cli_args.record_rr)
replay_last = get_last_event(cli_args.replay_rr)

print "Last known events: record={}, replay={}".format(record_last, replay_last)

minimum_events = { k: v + 1 for k, v in get_whens().items() }
if cli_args.instr_max:
    instr_count_max = int(cli_args.instr_max)
else:
    # get last instruction in failed replay
    gdb_run_both({
        record: "run {}".format(record_last),
        replay: "run {}".format(replay_last)
    }, timeout=None)

    gdb_run_both("reverse-continue", timeout=None)

    instr_count_max = get_instr_count(replay)

print "Failing replay instr count:", instr_count_max

def format_each(format_str, *cli_args):
    return { k: format_str.format(*[arg[k] for arg in cli_args]) \
            for k in cli_args[0] }

instr_to_event = sorteddict([(1, minimum_events)])
def record_instr_event():
    instr_counts = get_instr_counts()
    if instr_counts[record] == instr_counts[replay]:
        instr_to_event[instr_counts[record]] = get_whens()
    else:
        print "Warning: tried to record non-synchronized instr<->event"
        IPython.embed()

def goto_instr(instr):
    print "Moving to instr", instr
    disable_all()
    instr_counts = get_instr_counts()
    if instr in instr_to_event:
        run_instr = instr
    index = instr_to_event.keys().bisect_left(instr) - 1
    run_instr = instr_to_event.keys()[index]

    to_run = []
    for proc in both:
        if instr_counts[proc] > instr or instr_counts[proc] < run_instr:
            to_run.append(proc)
    gdb_run_both(format_each("run {}",
                { proc: instr_to_event[run_instr][proc] for proc in to_run }),
            timeout=None)

    run_instr = instr - DEBUG_COUNTER_PERIOD
    instr_counts = get_instr_counts()
    to_run = [proc for proc in both if instr_counts[proc] < run_instr]

    print "Moving to {} below {}".format(run_instr, instr)
    enable("debug_counter")
    condition("debug_counter",
            "cpus->tqh_first->rr_guest_instr_count >= {}".format(run_instr))
    gdb_run_both({ proc: "continue" for proc in to_run }, timeout=None)

    instr_counts = get_instr_counts()
    to_run = [proc for proc in both if instr_counts[proc] > instr]
    if to_run:
        print "Moving too-far ones back to {}".format(instr)
        print { proc: instr_counts[proc] for proc in to_run }
        condition("debug_counter",
                "cpus->tqh_first->rr_guest_instr_count <= {}".format(instr))
        gdb_run_both({ proc: "reverse-continue" for proc in to_run }, timeout=None)

    instr_counts = get_instr_counts()
    to_run = [proc for proc in both if instr_counts[proc] < instr]

    print "Moving precisely to", instr
    disable_all()
    enable("cpu_loop_exec_tb")
    condition("cpu_loop_exec_tb",
            "cpus->tqh_first->rr_guest_instr_count >= {}".format(instr))
    gdb_run_both({ proc: "continue" for proc in to_run }, timeout=None)

    condition("cpu_loop_exec_tb", "")
    instr_counts = get_instr_counts()
    FORWARDS = 0
    BACKWARDS = 1
    direction = FORWARDS
    while instr_counts[record] != instr_counts[replay]:
        if instr_counts[replay] == instr_count_max or \
                instr_counts[record] == instr_count_max:
            direction = BACKWARDS

        ahead = argmax(instr_counts)
        behind = other[ahead]
        if direction == FORWARDS:
            condition("cpu_loop_exec_tb",
                    "cpus->tqh_first->rr_guest_instr_count >= {}".format(
                        instr_counts[ahead]))
            gdb_run(behind, "continue", timeout=None)
        else:
            condition("cpu_loop_exec_tb",
                    "cpus->tqh_first->rr_guest_instr_count <= {}".format(
                        instr_counts[behind]))
            gdb_run(ahead, "reverse-continue", timeout=None)

        instr_counts = get_instr_counts()

    record_instr_event()
    return instr_counts[record]

maximum_events = get_whens()

disable_all()

if cli_args.instr_bounds:
    instr_bounds = map(int, cli_args.instr_bounds.split(','))
else:
    instr_bounds = [0, instr_count_max]

divergence_info = """
-----------------------------------------------------
Current divergence understanding:
    Instr range: [{instr_lo}, {instr_hi}]

    args to get back here:
    --instr-bounds={instr_lo},{instr_hi} \\
    --instr-max={instr_max}
------------------------------------------------------
"""

def print_divergence_info():
    print divergence_info.format(
        instr_lo=instr_bounds[0],
        instr_hi=instr_bounds[1],
        instr_max=instr_count_max
    )

whens = get_whens()
now_instr = instr_bounds[0]
last_now = None
while last_now != now_instr:
    print_divergence_info()

    mid = (instr_bounds[0] + instr_bounds[1]) / 2

    last_now = now_instr
    now_instr = goto_instr(mid)

    whens = get_whens()
    checksums = get_checksums()

    print
    print whens
    print "Current checksums:", checksums
    if checksums[replay] != checksums[record]: # after divergence
        instr_bounds[1] = min(instr_bounds[1], now_instr)
    else:
        instr_bounds[0] = max(instr_bounds[0], now_instr)

print "Haven't made progress since last iteration. Moving to memory checksum."
print_divergence_info()

disable_all()

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

diverged_registers = []
reg_size = get_same_value("sizeof ((CPUX86State*)0)->regs[0]")
num_regs = get_same_value("sizeof ((CPUX86State*)0)->regs") / reg_size
for reg in range(num_regs):
    values = get_value(both, "((CPUX86State*)cpus->tqh_first->env_ptr)->regs[{}]".format(reg))
    if values[record] != values[replay]:
        diverged_registers.append(reg)

# Return to latest converged instr
goto_instr(instr_bounds[0])

# x86 debug registers can only watch 4 locations of 8 bytes.
# we need to make sure to enforce that.
watches_set = 0
def watch(addrs, size):
    bits = size * 8
    gdb_run_both({
        proc: "watch *(uint{}_t)0x{:x}".format(bits, addrs[proc]) for proc in both
    })
    global watches_set
    watches_set += 1
    if watches_set >= 4:
        print "WARNING: Too much divergence! Not watching some diverged points."

disable_all()
reg_ptrs = get_value(both, "(uintptr_t)&(((CPUX86State*)cpus->tqh_first->env_ptr)->regs)")
for reg in diverged_registers:
    watch({ proc: reg_ptrs[proc] + reg * reg_size for proc in both }, reg_size)
    if watches_set >= 4: break

# Heuristic: Should watch each range at most once. So iterate over offset
# in outer loop, range in inner loop.
max_range = max([high - low for (high, low) in diverged_ranges])
for offset in range(0, max_range, 8):
    for low, high in diverged_ranges:
        watch_bytes = min(high - offset, 8)
        watch({ proc: ram_ptrs[proc] + offset for proc in both }, watch_bytes)
        if watches_set >= 4: break
    if watches_set >= 4: break

instr_counts = get_instr_counts()
while instr_counts[record] == instr_counts[replay] \
        and instr_counts[record] > 0 \
        and instr_counts[replay] < instr_count_max \
        and checksums_equal():
    gdb_run_both("continue", timeout=None)
    instr_counts = get_instr_counts()

backtraces = gdb_run_both("backtrace")
def show_backtrace(proc):
    print "{} BACKTRACE: ".format(proc.description.upper())
    print backtraces[proc]
    print

print
if instr_counts[record] > 0:
    print "Found first divergence!"
    if instr_counts[record] != instr_counts[replay]:
        ahead = argmax(instr_counts)
        behind = other[ahead]

        print "Saw behavior in {} not seen in {}.".format(
            behind.description, ahead.description)
        print
        show_backtrace(behind)
    else:
        print "Saw different behavior."
        print
        show_backtrace(record)
        show_backtrace(replay)
else:
    print "Failed to find exact divergence. Look at mem ranges {}".format(
            diverged_ranges)
    print_divergence_info()

IPython.embed()

gdb_run_both("quit")

record.join()
replay.join()
