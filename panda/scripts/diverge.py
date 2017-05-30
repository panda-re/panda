#!/usr/bin/python3
import IPython
import argparse
import operator
import os
import psutil
import re
import shlex
import subprocess
import sys

from blist import sorteddict
from errno import EAGAIN, EWOULDBLOCK
from multiprocessing.pool import ThreadPool
from os.path import join
from subprocess import check_call, CalledProcessError

from expect import Expect, TimeoutExpired
from tempdir import TempDir

DEBUG_COUNTER_PERIOD = 1 << 17

def check_output(args, **kwargs):
    kwargs['universal_newlines'] = kwargs.get('universal_newlines', True)
    return subprocess.check_output(args, **kwargs)

def get_default_rr_path():
    try:
        return check_output(["which", "rr"]).strip()
    except CalledProcessError:
        return None

def cached_property(func):
    def getter(self):
        if not hasattr(self, '_cache'):
            self._cache = {}
        if func not in self._cache:
            self._cache[func] = func(self)
        return self._cache[func]

    return property(fget=getter)

class RRInstance(object):
    def __init__(self, description, rr_replay, source_pane):
        self.description = description
        self.spawn_cmd = "{} replay {}".format(
            shlex.quote(cli_args.rr), shlex.quote(rr_replay))
        self.source_pane = source_pane

        self.breakpoints = {}
        self.watches_set = 0
        self.instr_to_event = sorteddict()

    def __repr__(self):
        return "RRInstance({!r})".format(self.description)

    # Runs in child process.
    def sendline(self, msg):
        check_call(['tmux', 'send-keys', '-t', self.pane, '-l', msg])
        check_call(['tmux', 'send-keys', '-t', self.pane, 'ENTER'])

    # Runs in child process.
    def kill(self):
        check_call(['tmux', 'kill-pane', '-t', self.pane])

    def __enter__(self):
        self.tempdir_obj = TempDir()
        tempdir = self.tempdir_obj.__enter__()
        logfile = join(tempdir, self.description + "out")
        os.mkfifo(logfile)
        bash_command = "{} 2>&1 | tee -i --output-error=warn {} | tee -i --output-error=warn {}_log.txt".format(
            self.spawn_cmd, shlex.quote(logfile), self.description)

        self.pane = check_output([
            'tmux', 'split-window', '-hdP',
            '-F', '#{pane_id}', '-t', pane,
            'bash', '-c', bash_command]).strip()

        self.proc = Expect(os.open(logfile, os.O_RDONLY | os.O_NONBLOCK), quiet=True)
        self.proc.expect("(rr) ")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type:
            self.kill()
        self.tempdir_obj.__exit__(exc_type, exc_value, traceback)

    def gdb(self, *args, **kwargs):
        timeout = kwargs.get('timeout', None)
        cmd = " ".join(map(str, args))
        print("(rr-{}) {}".format(self.description, cmd))
        sys.stdout.flush()

        while True:
            try:
                os.read(self.proc.fd, 1024)
            except OSError as e:
                if e.errno in [EAGAIN, EWOULDBLOCK]:
                    break
                else:
                    raise
        self.sendline(cmd)

        try:
            output = self.proc.expect("(rr) ", timeout=timeout)
        except TimeoutExpired:
            print(self.proc.sofar)
            print("EXCEPTION!")
            sys.stdout.flush()

        return output

    def quit(self):
        self.gdb("set confirm off")
        self.sendline("quit")

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

    def get_value(self, value_str):
        result = self.gdb("print/u", value_str)
        re_result = re.search(r"\$[0-9]+ = ([0-9]+)", result)
        if re_result:
            return int(re_result.group(1))
        else:
            print("get_value failed. result:", result)
            raise RuntimeError("get_value")

    def instr_count(self):
        return self.get_value("cpus->tqh_first->rr_guest_instr_count")

    @cached_property
    def instr_count_ptr(self):
        return self.get_value("&cpus->tqh_first->rr_guest_instr_count")

    def condition_instr(self, break_arg, op, instr):
        self.condition(
            break_arg, "*(uint64_t *){} {} {}".format(self.instr_count_ptr, op, instr))

    @cached_property
    def ram_ptr(self):
        return self.get_value(
            "memory_region_find(" +
                "get_system_memory(), 0x2000000, 1).mr->ram_block.host")

    def crc32_ram(self, low, size):
        step = 1 << 31 if size > (1 << 31) else size
        crc32s = 0
        for start in range(low, low + size, step):
            crc32s ^= self.get_value("crc32(0, {} + {}, {})".format(
                            hex(self.ram_ptr), hex(start), hex(step)))
        return crc32s

    @cached_property
    def ram_size(self):
        return self.get_value('ram_size')

    @cached_property
    def reg_size(self):
        return self.get_value("sizeof ((CPUX86State*)0)->regs[0]")

    @cached_property
    def num_regs(self):
        return self.get_value("sizeof ((CPUX86State*)0)->regs") // self.reg_size

    def env_value(self, name):
        return self.get_value("((CPUX86State*)cpus->tqh_first->env_ptr)->" + name)

    def env_ptr(self, name):
        return self.get_value("&((CPUX86State*)cpus->tqh_first->env_ptr)->" + name)

    def checksum(self):
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
            print("when failed. result:", result)
            raise RuntimeError("when")

    def cont(self):
        return self.gdb("continue", timeout=None)

    def reverse_cont(self):
        return self.gdb("reverse-continue", timeout=None)

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
            print()
            print("WARNING: Too much divergence! Not watching some diverged points.")
            print("(watchpoints are full...)")
            print()

    # watch a location in guest ram.
    def watch_ram(self, ram_addr, size):
        self.watch(self.ram_ptr + ram_addr, size)

    def record_instr_event(self):
        self.instr_to_event[self.instr_count()] = self.when()

    # Get as close to instr as possible.
    def goto(self, target_instr):
        print("Moving", self, "to instr", target_instr)
        self.disable_all()
        current_instr = self.instr_count()
        if target_instr in self.instr_to_event:
            run_instr = target_instr
        else:
            index = self.instr_to_event.keys().bisect_left(target_instr) - 1
            run_instr = self.instr_to_event.keys()[index]

        if current_instr > target_instr or current_instr < run_instr:
            self.run_event(self.instr_to_event[run_instr])

        # We should have now guaranteed that both will be in [run_instr, target_instr].
        # Now run them forwards to as close to target_instr as we can get.
        # debug_counter fires every 128k instrs, so move to last debug_counter
        # before desired instr count.
        run_instr = target_instr - DEBUG_COUNTER_PERIOD
        current_instr = self.instr_count()
        if current_instr < run_instr:
            print("Moving from {} to {} below {}".format(current_instr, run_instr, target_instr))
            self.enable("debug_counter")
            self.condition_instr("debug_counter", ">=", run_instr)
            self.cont()

        # unfortunately, we might have gone too far above. move back one
        # debug_counter fire if necessary.
        current_instr = self.instr_count()
        if current_instr > target_instr:
            print("Moving back to {}".format(target_instr))
            self.enable("debug_counter")
            self.condition_instr("debug_counter", "<=", target_instr)
            self.reverse_cont()

        current_instr = self.instr_count()
        if current_instr != target_instr:
            print("Moving precisely to", target_instr)
            self.disable_all()
            self.enable("cpu_loop_exec_tb")
            self.condition_instr("cpu_loop_exec_tb", ">=", target_instr)
            self.cont()

    # Go from beginning of program to execution of first TB after record/replay.
    def goto_first_tb(self):
        self.disable_all()
        self.enable("rr_do_begin_record")
        self.enable("rr_do_begin_replay")
        self.cont()
        self.enable("cpu_loop_exec_tb")
        self.cont()

    def find_last_instr(self, cli_args, last_event):
        self.goto_first_tb()

        if cli_args.instr_max is not None:
            instr_count_max = cli_args.instr_max
        else:
            # get last instruction in failed replay
            self.run_event(last_event)
            self.disable_all()
            self.enable("cpu_loop_exec_tb")
            self.reverse_cont()
            self.reverse_cont()
            instr_count_max = self.instr_count()

            # reset replay so it is in same state as record
            self.run_event(0)
            self.goto_first_tb()

        return instr_count_max

# Forward calls to self.procs, splitting arguments along the way.
class All(object):
    pool = ThreadPool(processes=2)

    def __init__(self, procs):
        self.procs = procs

    def split_args(self, args):
        out_args = { proc: [] for proc in self.procs }
        for arg in args:
            for proc in out_args:
                out_args[proc].append(arg[proc] if type(arg) == dict else arg)

        return out_args

    def __getattr__(self, name):
        def getattr_apply(proc_func_args):
            (proc, func_args) = proc_func_args
            return proc, getattr(proc, name)(*func_args)

        def result(*args, **kwargs):
            split_args = self.split_args(args)
            async_obj = self.pool.map_async(
                getattr_apply, split_args.items(), chunksize=1)
            # timeout necessary due to http://bugs.python.org/issue8844
            ret = dict(async_obj.get(9999999))
            if any([value is not None for value in ret.values()]):
                return ret

        return result

    def do(self, func_map):
        def star_apply(proc_func_func_args):
            (proc, (func, func_args)) = proc_func_func_args
            return proc, func(proc, *func_args)

        async_obj = self.pool.map_async(
            star_apply, func_map.items(), chunksize=1)
        # timeout necessary due to http://bugs.python.org/issue8844
        ret = dict(async_obj.get(9999999))
        if any([value is not None for value in ret.values()]):
            return ret

    def __dir__(self):
        return dir(self.procs[0]) + ['split_args', 'do']

    def __iter__(self):
        return iter(self.procs)

def values_equal(thedict):
    return len(set(thedict.values())) == 1

divergence_info = """
-----------------------------------------------------
Current divergence understanding:
    Instr range: [{instr_lo}, {instr_hi}]

    args to get back here:
    --instr-bounds={instr_lo},{instr_hi} \\
    --instr-max={instr_max}
------------------------------------------------------
"""

def print_divergence_info(instr_bounds, instr_count_max):
    print(divergence_info.format(
        instr_lo=instr_bounds[0],
        instr_hi=instr_bounds[1],
        instr_max=instr_count_max
    ))

def get_last_event(replay_dir):
    cmd = ("{} dump {} | grep global_time | tail -n 1 | " +
        "sed -E 's/^.*global_time:([0-9]+),.*$/\\1/'").format(cli_args.rr,
                                                                replay_dir)

    str_result = check_output(cmd, shell=True)
    return int(str_result)

def argmax(d):
    return max(d.items(), key=operator.itemgetter(1))[0]

def argmin(d):
    return min(d.items(), key=operator.itemgetter(1))[0]

class Diverge(object):
    def __init__(self, record, replay, cli_args):
        self.record = record
        self.replay = replay
        self.both = All([record, replay])
        self.other = { record: replay, replay: record }

    def bisect_memory(self):
        search_queue = [(0, self.record.ram_size)]
        divergences = []
        while search_queue:
            low, high = search_queue.pop()
            if high - low <= 4:
                print("Divergence occurred in range [{:08x}, {:08x}]".format(
                    low, high))
                divergences.append(low)
                continue

            size = (high - low) // 2
            crc32s_low = self.both.crc32_ram(low, size)
            crc32s_high = self.both.crc32_ram(low + size, size)

            if crc32s_low[self.record] != crc32s_low[self.replay]:
                search_queue.append((low, high - size))
            if crc32s_high[self.record] != crc32s_high[self.replay]:
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

    FORWARDS = 0
    BACKWARDS = 1
    # if FORWARDS, move behind up, and vice versa.
    # Assume only cpu_loop_exec_tb enabled.
    def get_closer(self, direction):
        instr_counts = self.both.instr_count()
        ahead = argmax(instr_counts)
        behind = self.other[ahead]
        if direction == Diverge.FORWARDS:
            behind.condition_instr(
                "cpu_loop_exec_tb", ">=", instr_counts[ahead])
            behind.cont()
        else:
            ahead.condition_instr(
                "cpu_loop_exec_tb", "<=", instr_counts[behind])
            ahead.reverse_cont()

    def sync_precise(self, target_instr, instr_count_max):
        self.both.disable_all()
        self.both.enable("cpu_loop_exec_tb")
        self.both.condition("cpu_loop_exec_tb", "")
        instr_counts = self.both.instr_count()
        direction = Diverge.FORWARDS
        while not values_equal(instr_counts):
            if max(instr_counts.values()) == instr_count_max:
                direction = Diverge.BACKWARDS

            self.get_closer(direction)
            instr_counts = self.both.instr_count()

        self.both.record_instr_event()
        return instr_counts[record]


    def bisect_time(self, instr_bounds, instr_count_max):
        whens = self.both.when()
        now_instr = instr_bounds[0]
        last_now = None
        while last_now != now_instr:
            print_divergence_info(instr_bounds, instr_count_max)

            mid = (instr_bounds[0] + instr_bounds[1]) // 2

            last_now = now_instr
            now_instr = self.goto_instr(mid, instr_count_max)

            whens = self.both.when()
            checksums = self.both.checksum()

            print()
            print(whens)
            print("Current checksums:", checksums)
            if not values_equal(checksums):  # after divergence
                # make right side of range smaller, i.e. new first divergence.
                instr_bounds[1] = min(instr_bounds[1], now_instr)
            else:
                # make left side of range smaller, i.e. new last converged point.
                instr_bounds[0] = max(instr_bounds[0], now_instr)

        return instr_bounds

    def check_registers(self):
        diverged_registers = []
        for reg in range(self.record.num_regs):
            reg_values = self.both.env_value("regs[{}]".format(reg))
            if not values_equal(reg_values):
                diverged_registers.append(reg)
        return diverged_registers

    def goto_instr(self, target_instr, instr_count_max):
        self.both.goto(target_instr)
        now_instr = self.sync_precise(target_instr, instr_count_max)
        self.both.record_instr_event()
        return now_instr

    def go(self):
        def cleanup_error():
            self.both.quit()
            self.record.join()
            self.replay.join()
            sys.exit(1)

        self.both.gdb("set confirm off")
        self.both.gdb("set pagination off")

        check_call(['tmux', 'select-layout', 'even-horizontal'])

        self.both.breakpoint("rr_do_begin_record")
        self.both.breakpoint("rr_do_begin_replay")
        self.both.breakpoint("cpu_loop_exec_tb")

        replay_last = get_last_event(cli_args.replay_rr)
        print("Last known replay event: {}".format(replay_last))

        result = self.both.do({
            self.record: (RRInstance.goto_first_tb, []),
            self.replay: (RRInstance.find_last_instr, [cli_args, replay_last])
        })

        instr_count_max = result[self.replay]
        assert instr_count_max is not None
        self.both.record_instr_event()

        print("Failing replay instr count:", instr_count_max)

        try:
            self.both.breakpoint("debug_counter")
        except AttributeError:
            print("Must run diverge.py on a debug build of panda. Run ./configure ",)
            print("with --enable-debug for this to work.")
            cleanup_error()

        if cli_args.instr_bounds:
            instr_bounds = [int(s) for s in cli_args.instr_bounds.split(',')]
        else:
            instr_bounds = [0, instr_count_max]

        # This is the most important function. Do a binary search over time to
        # find the first point of memory or register divergence.
        instr_bounds = self.bisect_time(instr_bounds, instr_count_max)

        print("Haven't made progress since last iteration. Moving to memory checksum.")
        print_divergence_info(instr_bounds, instr_count_max)

        # Find diverged memory ranges and registers.
        diverged_ranges = self.bisect_memory()
        diverged_registers = self.check_registers()

        diverged_pcs = not values_equal(self.both.env_value("eip"))

        print("Diverged memory addresses:",)
        print([(hex(low), hex(high)) for low, high in diverged_ranges])
        print("Diverged registers:", diverged_registers)
        print("Diverged eips:", diverged_pcs)

        # Return to latest converged instr
        now_instr = self.goto_instr(instr_bounds[0], instr_count_max)

        # Make sure we're actually at a converged point.
        # If we're more than 1000 instrs too far forward, make user intervene.
        if now_instr > instr_bounds[0] + 1000:
            print("WARNING: Processes are too far ahead of last divergence.")
            print("Please sync them manually behind", instr_bounds[0],)
            print("and continue.")
            IPython.embed()
            instr_counts = self.both.instr_count()
            assert values_equal(instr_counts)
            assert instr_counts[self.record] <= instr_bounds[0]
        else:
            # NB: in some cases, instr_bounds[0] (i.e. we observe the same instr
            # both converged and diverged. This should make sure we move before it
            # before setting watchpoints.
            if now_instr >= instr_bounds[1]:
                self.both.disable_all()
                self.both.enable("cpu_loop_exec_tb")
                self.both.condition_instr("cpu_loop_exec_tb", "<", instr_bounds[0])
                self.both.reverse_cont()
                while not values_equal(self.both.instr_count()):
                    print("Not synced.")
                    self.get_closer(Diverge.BACKWARDS)

        self.both.disable_all()
        if diverged_pcs:
            pc_ptrs = self.both.env_ptr("eip")
            self.both.watch(pc_ptrs, self.record.reg_size)

        for reg in diverged_registers:
            result = self.both.watch({
                proc: proc.env_ptr("regs[{}]".format(reg)) for proc in self.both
            }, self.record.reg_size)
            if self.record.watches_set >= 4: break

        # Heuristic: Should watch each range at most once. So iterate over offset
        # in outer loop, range in inner loop.
        max_range = max([high - low for (low, high) in diverged_ranges])
        max_range += max_range % 8
        for offset in range(0, max_range, 8):
            if self.record.watches_set >= 4: break
            for low, high in diverged_ranges:
                low -= low % 8
                watch_bytes = min(high - offset, 8)
                self.both.watch_ram(low + offset, watch_bytes)
                if self.record.watches_set >= 4: break

        if self.record.watches_set == 0:
            print("WARNING: Couldn't find any watchpoints to set at beginning of ",)
            print("divergence range. What do you want to do?")
            IPython.embed()

        instr_counts = self.both.instr_count()
        while values_equal(instr_counts) \
                and instr_counts[self.record] > 0 \
                and instr_counts[self.replay] < instr_count_max \
                and values_equal(self.both.checksum()):
            self.both.cont()
            instr_counts = self.both.instr_count()

        backtraces = self.both.gdb("backtrace")

        def show_backtrace(proc):
            print("{} BACKTRACE: ".format(proc.description.upper()))
            print(backtraces[proc])
            print()

        print()
        if instr_counts[self.record] > 0:
            print("Found first divergence!")
            if not values_equal(instr_counts):
                ahead = argmax(instr_counts)
                behind = self.other[ahead]

                print("Saw behavior in {} not seen in {}.".format(
                    behind.description, ahead.description))
                print()
                show_backtrace(behind)
            else:
                print("Saw different behavior.")
                print()
                show_backtrace(record)
                show_backtrace(replay)
        else:
            print("Failed to find exact divergence. Look at mem ranges {}".format(
                [(hex(lo), hex(hi)) for lo, hi in diverged_ranges]))
            print_divergence_info(instr_bounds, instr_count_max)

        self.both.gdb("set confirm on")
        self.both.gdb("set pagination on")
        IPython.embed()

def find_tmux_pane():
    tmux = False
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
            print("tmux mode on!")

    if tmux:
        panes = check_output(
            ['tmux', 'list-panes', '-a', '-F', '#{pane_id} #{pane_pid}'])
        for line in panes.splitlines():
            pane_id, pid_s = line.split()
            if int(pid_s) in parent_pids:
                return pane_id
    else:
        print("diverge.py must be run inside tmux. Please try again.")
        sys.exit(1)

if __name__ == '__main__':
    default_rr = get_default_rr_path()
    parser = argparse.ArgumentParser(
        description="A script to automatically find replay divergences")
    parser.add_argument("record_rr",
            help="Path to the rr directory for the recording replay")
    parser.add_argument("replay_rr",
            help="Path to the rr directory for the replay replay")
    parser.add_argument("--rr", default=default_rr,
            help="A path to the rr binary (default={})".format(default_rr))
    parser.add_argument("--instr-bounds",
            help=("Instruction bounds where divergence could have occurred."))
    parser.add_argument("--instr-max", type=int,
            help="Last instruction before replay failed.")
    cli_args = parser.parse_args()

    # Check arguments
    if not os.path.isfile(cli_args.rr):
        raise IOError("Cannot find rr bin at {}".format(cli_args.rr))
    if not os.path.isdir(cli_args.record_rr):
        raise IOError("Cannot find recording replay at {}".format(
                cli_args.record_rr))
    if not os.path.isdir(cli_args.replay_rr):
        raise IOError("Cannot find replay replay at {}".format(
                cli_args.replay_rr))

    assert cli_args.rr

    pane = find_tmux_pane()
    with RRInstance("replay", cli_args.replay_rr, pane) as replay, \
            RRInstance("record", cli_args.record_rr, pane) as record:
        diverge = Diverge(record, replay, cli_args)
        diverge.go()
