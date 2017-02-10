#!/usr/bin/python
import IPython
import argparse
import operator
import os
import pipes
import psutil
import re
import sys
import threading
import time

from blist import sorteddict
from errno import EAGAIN, EWOULDBLOCK
from multiprocessing import Process, Pipe
from multiprocessing.pool import ThreadPool
from os.path import join
from subprocess32 import check_call, check_output, CalledProcessError

from expect import Expect, TimeoutExpired
from tempdir import TempDir

DEBUG_COUNTER_PERIOD = 1 << 17

def get_default_rr_path():
    try:
        rr_path = check_output(["which", "rr"]).strip()
    except CalledProcessError:
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

tmux = False
pane = None
parent_pids = []
proc = psutil.Process(os.getpid())
while True:
    parent_pids.append(proc.pid)
    try:
        proc = psutil.Process(proc.ppid())
    except psutil.NoSuchProcess:
        break
    if 'tmux' in proc.name():
        tmux = True
        print "tmux mode on!"

if tmux:
    panes = check_output(['tmux', 'list-panes', '-a', '-F', '#{pane_id} #{pane_pid}'])
    for line in panes.splitlines():
        pane_id, pid_s = line.split()
        if int(pid_s) in parent_pids:
            pane = pane_id
            break
else:
    print "diverge.py must be run inside tmux. Please try again."
    sys.exit(1)

class RRInstance(Process):
    def __init__(self, description, rr_replay):
        parent_pipe, child_pipe = Pipe()
        super(RRInstance, self).__init__(target=self.go, args=[child_pipe])

        self.description = description
        self.pipe = parent_pipe
        self.spawn_cmd = "{} replay {}".format(
            pipes.quote(cli_args.rr), pipes.quote(rr_replay))

        self.breakpoints = {}
        self.watches_set = 0

    def __repr__(self):
        return "RRInstance({!r})".format(self.description)

    # Runs in child process.
    def sendline(self, msg):
        check_call(['tmux', 'send-keys', '-t', self.pane, '-l', msg])
        check_call(['tmux', 'send-keys', '-t', self.pane, 'ENTER'])

    # Runs in child process.
    def kill(self):
        check_call(['tmux', 'kill-pane', '-t', self.pane])

    # Runs in child process.
    def loop(self, pipe, tempdir):
        logfile = join(tempdir, self.description + "out")
        os.mkfifo(logfile)
        bash_command = "{} 2>&1 | tee -i --output-error=warn {} | tee -i --output-error=warn {}_log.txt".format(
            self.spawn_cmd, pipes.quote(logfile), self.description)
        self.pane = check_output([
            'tmux', 'split-window', '-hdP',
            '-F', '#{pane_id}', '-t', pane,
            'bash', '-c', bash_command]).strip()

        proc = Expect(os.open(logfile, os.O_RDONLY | os.O_NONBLOCK), quiet=True)
        proc.expect("(rr) ")

        while True:
            item, timeout = pipe.recv()
            # consume all waiting input before sending command.
            while True:
                try:
                    os.read(proc.fd, 1024)
                except OSError as e:
                    if e.errno in [EAGAIN, EWOULDBLOCK]:
                        break
                    else: raise
            self.sendline(item)

            if item == "quit":
                self.sendline("quit")
                break

            try:
                output = proc.expect("(rr) ", timeout=timeout)
            except TimeoutExpired:
                print proc.sofar
                print "EXCEPTION!"
                sys.stdout.flush()

            pipe.send(output)

    # Runs in child process.
    def go(self, pipe):
        try:
            with TempDir() as tempdir:
                self.loop(pipe, tempdir)
        except KeyboardInterrupt:
            self.kill()

    # Following run in parent process.
    def gdb(self, *args, **kwargs):
        timeout = kwargs.get('timeout', None)
        cmd = " ".join(map(str, args))
        print "(rr-{}) {}".format(self.description, cmd)
        sys.stdout.flush()
        self.pipe.send((cmd, timeout))
        return self.pipe.recv()

    def quit(self):
        self.pipe.send("quit")
        self.join()

    def breakpoint(self, break_arg):
        result = self.gdb("break", break_arg)
        bp_num = int(re.search(r"Breakpoint ([0-9]+) at", result).group(1))
        self.breakpoints[break_arg] = bp_num

    def disable_all(self):
        self.gdb("disable")

    def enable(self, break_arg):
        self.gdb("enable", self.breakpoints[break_arg])

    def condition(self, break_arg, cond):
        self.gdb("condition", self.breakpoints[break_arg], cond)

    def condition_instr(self, break_arg, op, instr):
        if not hasattr(self, 'instr_count_ptr'):
            self.instr_count_ptr = self.get_value("&cpus->tqh_first->rr_guest_instr_count")
        self.condition(break_arg, "*(uint64_t *){} {} {}".format(self.instr_count_ptr, op, instr))

    def get_value(self, value_str):
        result = self.gdb("print/u", value_str)
        re_result = re.search(r"\$[0-9]+ = ([0-9]+)", result)
        if re_result:
            return long(re_result.group(1))
        else:
            print "get_value failed. result:", result
            raise RuntimeError("get_value")

    def instr_count(self):
        return self.get_value("cpus->tqh_first->rr_guest_instr_count")

    def ram_ptr(self):
        if not hasattr(self, '_ram_ptr'):
            self._ram_ptr = self.get_value("memory_region_find(" + \
                    "get_system_memory(), 0x2000000, 1).mr->ram_block.host")
        return self._ram_ptr

    def crc32_ram(self, low, size):
        step = 1 << 31 if size > (1 << 31) else size
        crc32s = 0
        for start in range(low, low + size, step):
            crc32s ^= self.get_value("crc32(0, {} + {}, {})".format(
                            hex(self.ram_ptr()), hex(start), hex(step)))
        return crc32s

    def checksum(self):
        if not hasattr(self, 'ram_size'):
            self.ram_size = self.get_value('ram_size')
        # NB: Only run when you are at a breakpoint in CPU thread!
        memory = self.crc32_ram(0, self.ram_size)
        regs = self.get_value("rr_checksum_regs()")
        return (memory, regs)

    def when(self):
        result = self.gdb("when")
        re_result = re.search(r"Current event: ([0-9]+)", result)
        if re_result:
            return int(re_result.group(1))
        else:
            print "when failed. result:", result
            raise RuntimeError("when")

    def cont(self):
        self.gdb("continue", timeout=None)

    def reverse_cont(self):
        self.gdb("reverse-continue", timeout=None)

    def run_event(self, event):
        self.gdb("run", event, timeout=None)

    # x86 debug registers can only watch 4 locations of 8 bytes.
    # we need to make sure to enforce that.
    # returns true if can set more watchpoints. false if we're full up.
    def watch(self, addr, size):
        assert size in [1, 2, 4, 8]
        bits = size * 8
        self.gdb("watch *(uint{}_t *)0x{:x}".format(bits, addr))
        self.watches_set += 1
        if self.watches_set >= 4:
            print
            print "WARNING: Too much divergence! Not watching some diverged points."
            print "(watchpoints are full...)"
            print

    # watch a location in guest ram.
    def watch_ram(self, ram_addr, size):
        self.watch(self.ram_ptr() + ram_addr, size)

pool = ThreadPool(processes=2)

# Forward calls to self.procs, splitting arguments along the way.
class All(object):
    def __init__(self, procs):
        self.procs = procs

    def split_args(self, args):
        out_args = { proc: [] for proc in self.procs }
        for arg in args:
            for proc in out_args:
                out_args[proc].append(arg[proc] if type(arg) == dict else arg)

        return out_args

    def gdb(self, *args, **kwargs):
        split_args = self.split_args(args)
        timeout = kwargs.get('timeout', None)
        for proc, gdb_args in split_args.iteritems():
            cmd = " ".join(map(str, gdb_args))
            print "(rr-{}) {}".format(proc.description, cmd)
            proc.pipe.send((cmd, timeout))

        return { proc: proc.pipe.recv() for proc in self.procs }

    def __getattr__(self, name):
        def getattr_apply((proc, func_args)):
            return (proc, getattr(proc, name)(*func_args))

        def result(*args, **kwargs):
            split_args = self.split_args(args)
            return dict(pool.map(getattr_apply, split_args.iteritems(), chunksize=1))

        return result

record = RRInstance("record", cli_args.record_rr)
record.start()
time.sleep(0.3)
replay = RRInstance("replay", cli_args.replay_rr)
replay.start()

both = [record, replay]
Both = All(both)
other = { record: replay, replay: record }
descriptions = { record: "record", replay: "replay" }
objs = { "record": record, "replay": replay }

def cleanup_error():
    Both.gdb("quit")
    record.join()
    replay.join()
    sys.exit(1)

Both.gdb("set confirm off")
Both.gdb("set pagination off")

check_call(['tmux', 'select-layout', 'even-horizontal'])

Both.breakpoint("rr_do_begin_record")
Both.breakpoint("rr_do_begin_replay")
Both.breakpoint("cpu_loop_exec_tb")

def get_last_event(replay_dir):
    cmd = ("{} dump {} | grep global_time | tail -n 1 | " + \
        "sed -E 's/^.*global_time:([0-9]+),.*$/\\1/'").format(cli_args.rr, replay_dir)

    str_result = check_output(cmd, shell=True)
    return int(str_result)

replay_last = get_last_event(cli_args.replay_rr)
print "Last known replay event: {}".format(replay_last)

# Go from beginning of program to execution of first TB after record/replay.
def goto_first_tb(proc):
    proc.disable_all()
    proc.enable("rr_do_begin_record")
    proc.enable("rr_do_begin_replay")
    proc.cont()
    proc.enable("cpu_loop_exec_tb")
    proc.cont()

def start_replay(proc):
    global instr_count_max
    goto_first_tb(proc)

    if cli_args.instr_max:
        instr_count_max = int(cli_args.instr_max)
    else:
        # get last instruction in failed replay
        proc.run_event(replay_last)
        proc.disable_all()
        proc.enable("cpu_loop_exec_tb")
        proc.reverse_cont()
        proc.reverse_cont()
        instr_count_max = proc.instr_count()

        # reset replay so it is in same state as record
        proc.gdb("run 0")
        goto_first_tb(proc)

sync_thread = {
    record: threading.Thread(target=goto_first_tb, args=(record,)),
    replay: threading.Thread(target=start_replay, args=(replay,))
}

for proc in both: sync_thread[proc].start()
for proc in both: sync_thread[proc].join()

minimum_events = Both.when()

print "Failing replay instr count:", instr_count_max

try:
    Both.breakpoint("debug_counter")
except AttributeError:
    print "Must run diverge.py on a debug build of panda. Run ./configure ",
    print "with --enable-debug for this to work."
    cleanup_error()

def checksums_equal():
    return record.checksum() == replay.checksum()

instr_to_event = sorteddict([(0, minimum_events)])
def record_instr_event():
    instr_counts = Both.instr_count()
    if instr_counts[record] == instr_counts[replay]:
        instr_to_event[instr_counts[record]] = Both.when()
    else:
        print "Warning: tried to record non-synchronized instr<->event"
        IPython.embed()

def move_proc(proc, target_instr):
    print "Moving", proc, "to instr", target_instr
    proc.disable_all()
    current_instr = proc.instr_count()
    if target_instr in instr_to_event:
        run_instr = target_instr
    else:
        index = instr_to_event.keys().bisect_left(target_instr) - 1
        run_instr = instr_to_event.keys()[index]

    if current_instr > target_instr or current_instr < run_instr:
        proc.run_event(instr_to_event[run_instr][proc])

    # We should have now guaranteed that both will be in [run_instr, target_instr].
    # Now run them forwards to as close to target_instr as we can get.
    # debug_counter fires every 128k instrs, so move to last debug_counter
    # before desired instr count.
    run_instr = target_instr - DEBUG_COUNTER_PERIOD
    current_instr = proc.instr_count()
    if current_instr < run_instr:
        print "Moving from {} to {} below {}".format(current_instr, run_instr, target_instr)
        proc.enable("debug_counter")
        proc.condition_instr("debug_counter", ">=", run_instr)
        proc.cont()

    # unfortunately, we might have gone too far above. move back one
    # debug_counter fire if necessary.
    current_instr = proc.instr_count()
    if current_instr > target_instr:
        print "Moving back to {}".format(target_instr)
        proc.enable("debug_counter")
        proc.condition_instr("debug_counter", "<=", target_instr)
        proc.reverse_cont()

    current_instr = proc.instr_count()
    if current_instr != target_instr:
        print "Moving precisely to", target_instr
        proc.disable_all()
        proc.enable("cpu_loop_exec_tb")
        proc.condition_instr("cpu_loop_exec_tb", ">=", target_instr)
        proc.cont()

def sync_precise(target_instr):
    Both.disable_all()
    Both.enable("cpu_loop_exec_tb")
    Both.condition("cpu_loop_exec_tb", "")
    instr_counts = Both.instr_count()
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
            behind.condition_instr("cpu_loop_exec_tb", ">=", instr_counts[ahead])
            behind.cont()
        else:
            ahead.condition_instr("cpu_loop_exec_tb", "<=", instr_counts[behind])
            ahead.reverse_cont()

        instr_counts = Both.instr_count()

    record_instr_event()
    return instr_counts[record]

def goto_instr(target_instr):
    pool.map(lambda proc: move_proc(proc, target_instr), both, chunksize=1)
    now_instr = sync_precise(target_instr)
    record_instr_event()
    return now_instr

Both.disable_all()

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

whens = Both.when()
now_instr = instr_bounds[0]
last_now = None
while last_now != now_instr:
    print_divergence_info()

    mid = (instr_bounds[0] + instr_bounds[1]) / 2

    last_now = now_instr
    now_instr = goto_instr(mid)

    whens = Both.when()
    checksums = Both.checksum()

    print
    print whens
    print "Current checksums:", checksums
    if checksums[replay] != checksums[record]: # after divergence
        # make right side of range smaller, i.e. new first divergence.
        instr_bounds[1] = min(instr_bounds[1], now_instr)
    else:
        # make left side of range smaller, i.e. new last converged point.
        instr_bounds[0] = max(instr_bounds[0], now_instr)

print "Haven't made progress since last iteration. Moving to memory checksum."
print_divergence_info()

Both.disable_all()

def bisect_memory():
    ram_size = record.get_value("ram_size")
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
        crc32s_low = Both.crc32_ram(low, size)
        crc32s_high = Both.crc32_ram(low + size, size)

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

    return diverged_ranges

diverged_ranges = bisect_memory()

diverged_registers = []
reg_size = record.get_value("sizeof ((CPUX86State*)0)->regs[0]")
num_regs = record.get_value("sizeof ((CPUX86State*)0)->regs") / reg_size
for reg in range(num_regs):
    values = Both.get_value("((CPUX86State*)cpus->tqh_first->env_ptr)->regs[{}]".format(reg))
    if values[record] != values[replay]:
        diverged_registers.append(reg)

diverged_pcs = False
pcs = Both.get_value("((CPUX86State*)cpus->tqh_first->env_ptr)->eip")
if pcs[record] != pcs[replay]:
    diverged_pcs = True

print "Diverged memory addresses:",
print [(hex(low), hex(high)) for low, high in diverged_ranges]
print "Diverged registers:", diverged_registers
print "Diverged eips:", diverged_pcs

# Return to latest converged instr
goto_instr(instr_bounds[0])

Both.disable_all()
if diverged_pcs:
    pc_ptrs = Both.get_value("&((CPUX86State*)cpus->tqh_first->env_ptr)->eip")
    Both.watch(pc_ptrs, reg_size)

reg_ptrs = Both.get_value("&(((CPUX86State*)cpus->tqh_first->env_ptr)->regs)")
for reg in diverged_registers:
    result = Both.watch({ proc: reg_ptrs[proc] + reg * reg_size for proc in both }, reg_size)
    if record.watches_set >= 4: break

# Heuristic: Should watch each range at most once. So iterate over offset
# in outer loop, range in inner loop.
max_range = max([high - low for (low, high) in diverged_ranges])
max_range += max_range % 8
for offset in range(0, max_range, 8):
    if record.watches_set >= 4: break
    for low, high in diverged_ranges:
        low -= low % 8
        watch_bytes = min(high - offset, 8)
        Both.watch_ram(low + offset, watch_bytes)
        if record.watches_set >= 4: break

if record.watches_set == 0:
    print "WARNING: Couldn't find any watchpoints to set at beginning of ",
    print "divergence range. What do you want to do?"
    IPython.embed()

instr_counts = Both.instr_count()
while instr_counts[record] == instr_counts[replay] \
        and instr_counts[record] > 0 \
        and instr_counts[replay] < instr_count_max \
        and checksums_equal():
    Both.gdb("continue", timeout=None)
    instr_counts = Both.instr_count()

backtraces = Both.gdb("backtrace")
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
        [(hex(low), hex(high)) for low, high in diverged_ranges])
    print_divergence_info()

IPython.embed()

Both.gdb("quit")

record.join()
replay.join()
