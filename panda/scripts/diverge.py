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

class ArchConfig(object):
    def __init__(self, cpu_state_name, pc_name, reg_name):
        self.cpu_state_name = cpu_state_name
        self.pc_name = pc_name
        self.reg_name = reg_name

SUPPORTED_ARCHS = {
    'i386': ArchConfig('CPUX86State', 'eip', 'regs'),
    'x86_64': ArchConfig('CPUX86State', 'eip', 'regs'),
    'arm': ArchConfig('CPUARMState', 'pc', 'regs'),
    'ppc': ArchConfig('CPUPPCState', 'lr', 'gpr')
}

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

def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]

def re_search_int(result_re, result):
    re_result = re.search(result_re, result)
    if re_result:
        return int(re_result.group(1))
    else:
        print("re_search_int failed. result:", result)
        raise RuntimeError("re_search_int")

class Watch(object):
    def render(self, procs): raise NotImplemented()
    def __repr__(self): raise NotImplemented()
    def __str__(self): return repr(self)

class WatchEIP(Watch):
    def render(self, proc):
        return proc.env_ptr(proc.arch.pc_name), proc.reg_size

    def __repr__(self):
        return "WatchEIP()"

class WatchRAM(Watch):
    def __init__(self, addr, size):
        self.addr = addr
        self.size = size

    def render(self, proc):
        return proc.ram_ptr + self.addr, self.size

    def __repr__(self):
        return "WatchRAM({:#x}, {})".format(self.addr, self.size)

class WatchReg(Watch):
    def __init__(self, reg_num):
        self.reg_num = reg_num

    def render(self, proc):
        return proc.env_ptr("{}[{}]".format(proc.arch.reg_name, self.reg_num)), proc.reg_size

    def __repr__(self):
        return "WatchReg({})".format(self.reg_num)

class RRInstance(object):
    def __init__(self, description, rr_replay, source_pane):
        self.rr_replay = rr_replay
        self.description = description
        self.spawn_cmd = "{} replay {}".format(
            shlex.quote(cli_args.rr), shlex.quote(rr_replay))
        self.source_pane = source_pane

        self.breakpoints = {}
        self.watches_set = 0
        self.instr_to_checkpoint = sorteddict()

    def __repr__(self):
        return "RRInstance({!r})".format(self.description)

    @cached_property
    def arch(self):
        rr_ps = check_output([cli_args.rr, 'ps', self.rr_replay])
        qemu_regex = r"qemu-system-({})".format("|".join(SUPPORTED_ARCHS.keys()))
        re_result = re.search(qemu_regex, rr_ps)
        if not re_result: raise RuntimeError("Unsupported architecture!")
        return SUPPORTED_ARCHS[re_result.group(1)]

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
        try:
            self.proc.expect("(rr) ", timeout=3)
        except TimeoutExpired:
            print(self.proc.sofar)
            raise
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

        expect_prompt = kwargs.get("expect_prompt", "(rr) ")

        while True:
            try:
                os.read(self.proc.fd, 1024)
            except OSError as e:
                if e.errno in [EAGAIN, EWOULDBLOCK]: break
                else: raise
        self.sendline(cmd)

        try:
            output = self.proc.expect(expect_prompt, timeout=timeout)
        except TimeoutExpired:
            print(self.proc.sofar)
            print("EXCEPTION!")
            sys.stdout.flush()

        if output.endswith(expect_prompt): output = output[:-len(expect_prompt)]
        if output.startswith(cmd): output = output[len(cmd):]
        return output.strip()

    def quit(self):
        self.gdb("set confirm off")
        self.sendline("quit")

    def gdb_int_re(self, result_re, *args):
        result = self.gdb(*args)
        return re_search_int(result_re, result)

    def breakpoint(self, break_arg):
        bp_num = self.gdb_int_re(r"Breakpoint ([0-9]+) at", "break", break_arg)
        self.breakpoints[break_arg] = bp_num

    def disable_all(self):
        self.gdb("disable")
        self.watches_set = 0

    def enable(self, break_arg):
        self.gdb("enable", self.breakpoints[break_arg])

    def enable_only(self, *breaks):
        self.disable_all()
        for break_arg in breaks:
            self.enable(break_arg)

    def condition(self, break_arg, cond):
        self.gdb("condition", self.breakpoints[break_arg], cond)

    def display(self, cmd):
        self.gdb("display", cmd)

    def checkpoint(self):
        return self.gdb_int_re(r"Checkpoint ([0-9]+) at", "checkpoint")

    def restart(self, checkpoint):
        self.disable_all()
        self.gdb("restart", checkpoint)

    def restart_instr(self, instr):
        self.restart(self.instr_to_checkpoint[instr])

    def get_value(self, expr):
        return self.gdb_int_re(r"\$[0-9]+ = ([0-9]+)", "print/u", expr)

    def instr_count(self):
        return self.get_value("cpus->tqh_first->rr_guest_instr_count")

    @cached_property
    def instr_count_ptr(self):
        return self.get_value("&cpus->tqh_first->rr_guest_instr_count")

    def condition_instr(self, break_arg, op, instr):
        self.condition(
            break_arg, "*(uint64_t *){} {} {}".format(self.instr_count_ptr, op, instr))

    def set_breakpoint_commands(self, break_num):
        self.gdb("commands", break_num, expect_prompt = ">")
        # self.gdb("p/u cpus->tqh_first->rr_guest_instr_count", expect_prompt = ">")
        self.gdb("call target_disas(stdout, cpu, tb->pc, tb->size, 0)", expect_prompt = ">")
        self.gdb("end")

    def display_commands(self):
        self.display("cpus->tqh_first->rr_guest_instr_count")
        self.display("cpus->tqh_first->exception_index")
        self.display("cpus->tqh_first->exit_request")
        self.gdb("set $env = ((CPUPPCState*) cpus->tqh_first->env_ptr)")
        self.display("$env->pending_interrupts")

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
        return self.get_value("sizeof (({}*)0)->{}[0]".format(
            self.arch.cpu_state_name, self.arch.reg_name))

    @cached_property
    def num_regs(self):
        return self.get_value("sizeof (({}*)0)->{}".format(
            self.arch.cpu_state_name, self.arch.reg_name)) // self.reg_size

    def env_value(self, name):
        return self.get_value("(({}*)cpus->tqh_first->env_ptr)->{}".format(
            self.arch.cpu_state_name, name))

    def env_ptr(self, name):
        return self.get_value("&(({}*)cpus->tqh_first->env_ptr)->{}".format(
            self.arch.cpu_state_name, name))

    def checksum(self):
        # NB: Only run when you are at a breakpoint in CPU thread!
        memory = self.crc32_ram(0, self.ram_size)
        regs = self.get_value("rr_checksum_regs()")
        return (memory, regs)

    def when(self):
        return self.gdb_int_re(r"Current event: ([0-9]+)", "when")

    def cont(self):
        return self.gdb("continue", timeout=None)

    def reverse_cont(self):
        return self.gdb("reverse-continue", timeout=None)

    # x86 debug registers can only watch 4 locations of 8 bytes.
    # we need to make sure to enforce that.
    # returns true if can set more watchpoints. false if we're full up.
    def watch_addr(self, addr, size):
        assert size in [1, 2, 4, 8]
        bits = size * 8
        num = self.gdb_int_re(r"Hardware watchpoint ([0-9]+):",
                              "watch", "*(uint{}_t *)0x{:x}".format(bits, addr))
        self.watches_set += 1
        if self.watches_set > 4:
            print()
            print("WARNING: Too much divergence! Not watching some diverged points.")
            print("(watchpoints are full...)")
            print()

        return num

    def watch(self, watchpoint):
        return self.watch_addr(*watchpoint.render(self))

    def record_instr_checkpoint(self):
        instr_count = self.instr_count()
        if instr_count not in self.instr_to_checkpoint:
            self.instr_to_checkpoint[instr_count] = self.checkpoint()
        return self.instr_to_checkpoint[instr_count]

    # Get as close to instr as possible.
    def goto_rough(self, target_instr):
        print("Moving", self, "to instr", target_instr)
        current_instr = self.instr_count()
        if target_instr in self.instr_to_checkpoint:
            run_instr = target_instr
        else:
            index = self.instr_to_checkpoint.keys().bisect_left(target_instr) - 1
            run_instr = self.instr_to_checkpoint.keys()[index]

        if current_instr > target_instr or current_instr < run_instr:
            self.restart(self.instr_to_checkpoint[run_instr])

        # We should have now guaranteed that both will be in [run_instr, target_instr].
        # Now run them forwards to as close to target_instr as we can get.
        # debug_counter fires every 128k instrs, so move to last debug_counter
        # before desired instr count.
        run_instr = target_instr - DEBUG_COUNTER_PERIOD
        current_instr = self.instr_count()
        if current_instr < run_instr:
            print("Moving from {} to {} below {}".format(current_instr, run_instr, target_instr))
            self.enable_only("debug_counter")
            self.condition_instr("debug_counter", ">=", run_instr)
            self.cont()
            current_instr = self.instr_count()

        # unfortunately, we might have gone too far above. move back one
        # debug_counter fire if necessary.
        if current_instr > target_instr:
            print("Moving back to {}".format(target_instr))
            self.enable_only("debug_counter")
            self.condition_instr("debug_counter", "<=", target_instr)
            self.reverse_cont()
            current_instr = self.instr_count()

        if current_instr != target_instr:
            print("Moving precisely to", target_instr)
            self.enable_only("cpu_loop_exec_tb")
            self.condition_instr("cpu_loop_exec_tb", ">=", target_instr)
            self.cont()

    # Go from beginning of program to execution of first TB after record/replay.
    # Return number of that checkpoint.
    def goto_first_tb(self):
        self.enable_only("rr_do_begin_record", "rr_do_begin_replay")
        self.cont()
        self.enable_only("cpu_loop_exec_tb")
        self.cont()
        return self.record_instr_checkpoint()

    def find_last_instr(self, cli_args, last_event):
        first_tb_checkpoint = self.goto_first_tb()

        if cli_args.instr_max is not None:
            instr_count_max = cli_args.instr_max
        else:
            # get last instruction in failed replay
            self.gdb("run", last_event, timeout=None)
            self.enable_only("cpu_loop_exec_tb")
            self.reverse_cont() # go backwards through failure signal
            self.reverse_cont() # land on last TB exec
            instr_count_max = self.instr_count()

            # reset replay so it is in same state as record
            self.restart(first_tb_checkpoint)

        return instr_count_max

# Forward calls to self.procs, splitting arguments along the way.
class All(object):
    pool = ThreadPool(processes=2)

    def __init__(self, procs, unify=False):
        self.procs = procs
        self.unify = unify # unify results of calls?
        if not unify:
            self.same = All(procs, unify=True)

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
            ret = dict(async_obj.get(None))
            if any([value is not None for value in ret.values()]):
                if self.unify:
                    assert values_equal(ret)
                    return next(iter(ret.values()))
                else:
                    return ret

        return result

    def do(self, func_map):
        def star_apply(proc_func_func_args):
            (proc, (func, func_args)) = proc_func_func_args
            return proc, func(proc, *func_args)

        async_obj = self.pool.map_async(
            star_apply, func_map.items(), chunksize=1)
        # timeout necessary due to http://bugs.python.org/issue8844
        ret = dict(async_obj.get(None))
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
    def __init__(self, record, replay):
        self.record = record
        self.replay = replay
        self.both = All([record, replay])
        self.other = { record: replay, replay: record }

    def print_divergence_info(self, instr_bounds):
        print(divergence_info.format(
            instr_lo=instr_bounds[0],
            instr_hi=instr_bounds[1],
            instr_max=self.instr_count_max
        ))

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

    def sync_precise(self, target_instr):
        self.both.enable_only("cpu_loop_exec_tb")
        self.both.condition("cpu_loop_exec_tb", "")
        instr_counts = self.both.instr_count()
        direction = Diverge.FORWARDS
        while not values_equal(instr_counts):
            if max(instr_counts.values()) == self.instr_count_max:
                direction = Diverge.BACKWARDS

            self.get_closer(direction)
            instr_counts = self.both.instr_count()

        self.both.record_instr_checkpoint()
        return instr_counts[record]


    def bisect_time(self, instr_bounds):
        now_instr = instr_bounds[0]
        last_now = None
        while last_now != now_instr:
            self.print_divergence_info(instr_bounds)

            mid = (instr_bounds[0] + instr_bounds[1]) // 2

            last_now = now_instr
            now_instr = self.goto_instr(mid)

            checksums = self.both.checksum()

            print()
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
            reg_values = self.both.env_value("{}[{}]".format(
                self.record.arch.reg_name, reg))
            if not values_equal(reg_values):
                diverged_registers.append(reg)
        return diverged_registers

    def goto_instr(self, target_instr, strict=False):
        self.both.goto_rough(target_instr)
        now_instr = self.sync_precise(target_instr)
        if strict and target_instr != now_instr:
            print("WARNING: Failed to sync exactly. Please fix manually.")
            print("Trying to go to instr {}.".format(target_instr))
            IPython.embed()
        self.both.record_instr_checkpoint()
        return now_instr

    def find_precise_divergence(self, instr_bounds, diverged_ranges,
                                diverged_registers, diverged_pcs):
        watches = [WatchReg(reg) for reg in diverged_registers]
        if diverged_pcs: watches.append(WatchEIP())

        for low, high in diverged_ranges:
            if low % 8 != 0:
                assert low % 8 == 4
                watches.append(WatchRAM(low, 4))
                low += 4
            while low < high:
                watches.append(WatchRAM(low, min(8, high - low)))
                low += 8

        if len(watches) == 0:
            print("WARNING: Couldn't find any watchpoints to set at beginning of ",)
            print("divergence range. What do you want to do?")
            IPython.embed()

        self.goto_instr(instr_bounds[0], strict=True)

        # Unfortunately, only 4 hardware watchpoints on x86 hosts. So we check
        # potential divergence points in groups of 4, finding the first to
        # diverge in each group. That reduces potential first divergence points
        # by a factor of 2 in each loop.
        while True:
            new_watches = []
            for watches_chunk in chunks(watches, 4):
                num_to_watch_dict = {}
                self.both.restart_instr(instr_bounds[0])
                for watch in watches_chunk:
                    num_to_watch_dict[self.both.same.watch(watch)] = watch

                instr_counts = self.both.instr_count()
                while values_equal(instr_counts) \
                        and instr_counts[self.record] > 0 \
                        and instr_counts[self.replay] < self.instr_count_max \
                        and values_equal(self.both.checksum()):
                    hit = self.both.cont()
                    instr_counts = self.both.instr_count()

                hit_watches = {}
                for proc in hit:
                    try:
                        hit_watches[proc] = num_to_watch_dict[
                            re_search_int(r"hit Hardware watchpoint ([0-9]+):",
                                        hit[proc])
                        ]
                    except RuntimeError:
                        # one of the processes has hit the end
                        pass
                new_watches.extend(set(hit_watches.values()))

            if len(watches) == len(new_watches): break
            watches = new_watches
            assert len(watches) > 0

        return hit_watches

    def go(self):
        def cleanup_error():
            self.both.quit()
            sys.exit(1)

        self.both.gdb("set confirm off")
        self.both.gdb("set pagination off")

        check_call(['tmux', 'select-layout', 'even-horizontal'])

        self.both.breakpoint("rr_do_begin_record")
        self.both.breakpoint("rr_do_begin_replay")
        self.both.breakpoint("cpu_loop_exec_tb")

        try:
            self.both.breakpoint("debug_counter")
        except RuntimeError:
            print("Must run diverge.py on a debug build of panda. Run ./configure ",)
            print("with --enable-debug for this to work.")
            cleanup_error()

        replay_last = get_last_event(cli_args.replay_rr)
        print("Last known replay event: {}".format(replay_last))

        result = self.both.do({
            self.record: (RRInstance.goto_first_tb, []),
            self.replay: (RRInstance.find_last_instr, [cli_args, replay_last])
        })

        # This is a guardrail to avoid moving the recording past the last
        # instr in the (failing) replay.
        self.instr_count_max = result[self.replay]
        assert self.instr_count_max is not None

        print("Failing replay instr count:", self.instr_count_max)

        if cli_args.instr_bounds:
            instr_bounds = [int(s) for s in cli_args.instr_bounds.split(',')]
            self.goto_instr(instr_bounds[0], strict=True)
        else:
            instr_bounds = [0, self.instr_count_max]

        if cli_args.skip_bisect_time:
            self.goto_instr(instr_bounds[1], strict=True)
        else:
            # This is the most important function. Do a binary search over time
            # to find the first point of memory or register divergence.
            instr_bounds = self.bisect_time(instr_bounds)
            print("Haven't made progress since last iteration. Moving to memory checksum.")
            self.goto_instr(instr_bounds[1])

        self.print_divergence_info(instr_bounds)

        # Find diverged memory ranges and registers.
        diverged_ranges = self.bisect_memory()
        diverged_registers = self.check_registers()
        diverged_pcs = not values_equal(self.both.env_value(self.record.arch.pc_name))

        print("Diverged memory addresses:",)
        print([(hex(lo), hex(hi)) for lo, hi in diverged_ranges])
        print("Diverged registers:", diverged_registers)
        print("Diverged eips:", diverged_pcs)

        hit_watches = self.find_precise_divergence(
            instr_bounds, diverged_ranges, diverged_registers, diverged_pcs
        )

        # Now we are precisely at first point of divergence
        instr_counts = self.both.instr_count()
        backtraces = self.both.gdb("backtrace")

        def show_backtrace(proc):
            print("{} stopped at {}".format(proc.description.upper(),
                                            hit_watches[proc]))
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
            self.print_divergence_info(instr_bounds)

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
    parser.add_argument("--skip-bisect-time", action='store_true',
            help="Skip binary search over time (use provided instr bounds).")
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
        diverge = Diverge(record, replay)
        diverge.go()
