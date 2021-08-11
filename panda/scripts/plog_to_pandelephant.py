#!/usr/bin/python3
"""
Module for converting from PANDAlog (plog) files to a Pandelephant database
"""

import argparse
import collections
import sys
import time

import pandelephant
from pandare import PLogReader

# TODO: add more steps that should be skipped to the steps list
# and then check `if 'stepname' not in skip_steps: ...` before running the steps
steps = ["threadslices", "asid_libraries"]

def hasfield(msg, field_name):
    '''
    HasField will raise an exception if that isnt a possible field name
    so this version translates that into a False
    '''
    try:
        return msg.HasField(field_name)
    except:
        return False

def time_log(arg):
    '''
    Decorator to log timing information.
    Use as either @time_log def myfunc() or @time_log("Some Name") def anotherfunc()

    Will print timing information for the wrapped function along with the provided
    name or the function name.
    '''

    def helper(name, f, *args, **kwargs):
        t1 = time.time()
        rv = f(*args, **kwargs)
        t2 = time.time()
        print(f"{name} completed in {t2-t1:.2f}\n" + "_" * 60)
        return rv

    def unnamed(*args, **kwargs):
        return helper(arg.__name__, arg, *args, **kwargs)
    def named(target_func):
        def _named(*args, **kwargs):
            return helper(arg, target_func, *args, **kwargs)
        return _named

    if callable(arg): # If arg is callabale, assume it's not the function name and use `unnamed`
        return unnamed
    # Otherwise assume arg is name and we use `named` to grab the target func
    return named

CollectedThread = collections.namedtuple(
    "CollectedThread", ["ProcessId", "ParentProcessId", "ThreadId", "CreateTime"]
)
CollectedProcess = collections.namedtuple(
    "CollectedProcess", ["ProcessId", "ParentProcessId"]
)
CollectedThreadSlice = collections.namedtuple(
    "CollectedThreadSlice", ["FirstInstructionCount", "LastInstructionCount", "Thread"]
)
CollectedMappingSlice = collections.namedtuple(
    "CollectedMappingSlice", ["InstructionCount", "AddressSpaceId", "Mappings"]
)
CollectedMapping = collections.namedtuple(
    "CollectedMapping", ["Name", "File", "BaseAddress", "Size"]
)
BetterCollectedMapping = collections.namedtuple(
    "BetterCollectedMapping",
    ["AddressSpaceId", "Process", "Name", "File", "BaseAddress", "Size"],
)
CollectedCodePoint = collections.namedtuple("CollectedCodePoint", ["Mapping", "Offset"])
CollectedSyscall = collections.namedtuple(
    "CollectedSyscall",
    ["Name", "RetVal", "Thread", "InstructionCount", "Arguments", "ProgramCounter"],
)
CollectedSyscallArgument = collections.namedtuple(
    "CollectedSyscallArgument", ["Name", "Type", "Value"]
)
CollectedTaintFlow = collections.namedtuple(
    "CollectedTaintFlow",
    [
        "IsStore",
        "SourceCodePoint",
        "SourceThread",
        "SourceInstructionCount",
        "SinkCodePoint",
        "SinkThread",
        "SinkInstructionCount",
    ],
)

class PLogToPandelephant:
    """
    Class for converting PANDAlog (plog) files to a pandelephant database. Run directly with:
        python -m pandare.PlogToPandelphant -db_url X -pandalog Y -exec_name Z
    """

    @time_log("Full import process")
    def __init__(self, pandalog, db_url, exec_name, skip_steps=None):
        self.pandalog = pandalog
        self.db_url = db_url
        self.exec_name = exec_name
        self.skip_steps = skip_steps if skip_steps else []

        self.ds = pandelephant.PandaDatastore(db_url)
        self.execution = self.CreateExecutionIfNeeded()

        self.CollectThreadsAndProcesses()

        self.AssociateThreadsAndProcesses()

        self.CollectProcessMemoryMappings()

        print(
            "Got {} BetterMappings...".format(
                sum(
                    len(procmaps.keys())
                    for procmaps in self.CollectedBetterMappingRanges.values()
                )
            )
        )

        for proc in self.processes:
            print(
                "\tProcess (ProcessId {} ParentProcessId {}) has {} Threads {} Mappings".format(
                    proc.ProcessId,
                    proc.ParentProcessId,
                    len(self.proc2threads[proc]),
                    len(self.CollectedBetterMappingRanges[proc].keys()),
                )
            )

            for mapping, (
                FirstInstructionCount,
                LastInstructionCount,
            ) in self.CollectedBetterMappingRanges[proc].items():
                print(
                    '\t\tFrom Instruction {} - {} in Address Space {:#x} Mapping {} File {}" \
                        "BaseAddress {:#x} Size {:#x}'.format(
                        FirstInstructionCount,
                        LastInstructionCount,
                        mapping.AddressSpaceId,
                        mapping.Name,
                        mapping.File,
                        mapping.BaseAddress,
                        mapping.Size,
                    )
                )

        self.CollectTaintFlowsAndSyscalls()

        print(
            "Collected {} Taint Flows {} Syscalls {} Code Points".format(
                len(self.CollectedTaintFlows),
                len(self.CollectedSyscalls),
                len(self.CollectedCodePoints),
            )
        )

        self.ConvertProcessThreadsMappingsToDatabase()

        self.ConvertTaintFlowsToDatabase()
        self.ConvertSyscallsToDatabase()

        # // init

    @time_log
    def AssociateThreadsAndProcesses(self):
        # associate threads and procs
        print("Associating Threads and Processes...")
        self.thread2proc = {
            thread: CollectedProcess(
                ProcessId=thread.ProcessId, ParentProcessId=thread.ParentProcessId
            )
            for thread in self.threads
        }
        self.proc2threads = {proc: set() for proc in self.processes}
        for thread in self.threads:
            self.proc2threads[(thread.ProcessId, thread.ParentProcessId)].add(thread)
        # newthreads = set([])  # All threads observed
        # DuplicateCheck = set((thread.ThreadId, thread.CreateTime)
        #                     for thread in self.threads)

        # if len(DuplicateCheck) != len(self.thread2proc.keys()):
        #     raise Exception("Threads are not unique in (ThreadId, CreateTime)..."\
        #     "If you think this should be ingestable, change this line...")

        for proc in self.proc2threads:
            print(
                "Process (ProcessId {} ParentProcessId {}) has {} Threads".format(
                    proc.ProcessId, proc.ParentProcessId, len(self.proc2threads[proc])
                )
            )

            for thread in self.proc2threads[proc]:
                if thread in self.thread_names:
                    print(
                        "\tThread (ThreadId {} CreateTime {:#x}) names: {}".format(
                            thread.ThreadId,
                            thread.CreateTime,
                            self.thread_names[thread],
                        )
                    )

    @time_log
    def CollectThreadsAndProcesses(self):
        print("First pass over plog (Gathering Processes and Threads)...")

        """
        Why don't we just gather these on the fly? Because there are multiple sources
        for this information and they have to be reconciled. It's oddly tricky to
        get a consistent view out of a replay of the set of threads and processes and
        their names.

        One could check at every basic block (by invoking OSI) but that would be very
        slow.  So we check at a few std temporal points (syscall, every 100 bb,
        asid_info logging points) and reconcile.

        Better would be if we had callback on after-scheduler-changes-proc s.t. we
        could obtain proc/thread.  TODO: if we have proc_trace messages, that's
        exactly what we have
        """

        # thread is (pid, ppid, tid, create_time)
        # process is (pid, ppid)
        self.processes = set()
        self.threads = set()
        self.thread_slices = set()
        self.thread_names = {}

        def CollectFrom_asid_libraries(msg):
            thread = CollectedThread(
                ProcessId=msg.pid,
                ParentProcessId=msg.ppid,
                ThreadId=msg.tid,
                CreateTime=msg.create_time,
            )
            # there might be several names for a tid
            if thread in self.thread_names.keys():
                self.thread_names[thread].add(msg.proc_name)
            else:
                self.thread_names[thread] = set([msg.proc_name])
            self.threads.add(thread)
            self.processes.add(
                CollectedProcess(ProcessId=msg.pid, ParentProcessId=msg.ppid)
            )

        def CollectFrom_asid_info(msg):
            for tid in msg.tids:
                thread = CollectedThread(
                    ProcessId=msg.pid,
                    ParentProcessId=msg.ppid,
                    ThreadId=tid,
                    CreateTime=msg.create_time,
                )
                if thread in self.thread_names.keys():
                    for name in msg.names:
                        self.thread_names[thread].add(name)
                else:
                    self.thread_names[thread] = set(msg.names)
                self.threads.add(thread)
                self.thread_slices.add(
                    CollectedThreadSlice(
                        FirstInstructionCount=msg.start_instr,
                        LastInstructionCount=msg.end_instr,
                        Thread=thread,
                    )
                )
            self.processes.add(
                CollectedProcess(ProcessId=msg.pid, ParentProcessId=msg.ppid)
            )

        def CollectFrom_taint_flow(msg):
            source_thread = msg.source.cp.thread
            self.threads.add(
                CollectedThread(
                    ProcessId=source_thread.pid,
                    ParentProcessId=source_thread.ppid,
                    ThreadId=source_thread.tid,
                    CreateTime=source_thread.create_time,
                )
            )
            self.processes.add(
                CollectedProcess(
                    ProcessId=source_thread.pid, ParentProcessId=source_thread.ppid
                )
            )
            sink_thread = msg.sink.cp.thread
            self.threads.add(
                CollectedThread(
                    ProcessId=sink_thread.pid,
                    ParentProcessId=sink_thread.ppid,
                    ThreadId=sink_thread.tid,
                    CreateTime=sink_thread.create_time,
                )
            )
            self.processes.add(
                CollectedProcess(
                    ProcessId=sink_thread.pid, ParentProcessId=sink_thread.ppid
                )
            )

        def CollectFrom_syscall(msg):
            self.threads.add(
                CollectedThread(
                    ProcessId=msg.pid,
                    ParentProcessId=msg.ppid,
                    ThreadId=msg.tid,
                    CreateTime=msg.create_time,
                )
            )
            self.processes.add(
                CollectedProcess(ProcessId=msg.pid, ParentProcessId=msg.ppid)
            )

        last_thread_info = None

        def CollectFrom_proc_trace(msg):
            thread = CollectedThread(
                ProcessId=msg.pid,
                ParentProcessId=msg.ppid,
                ThreadId=msg.tid,
                CreateTime=msg.create_time,
            )
            if thread in self.thread_names.keys():
                self.thread_names[thread].add(msg.name)
            else:
                self.thread_names[thread] = set([msg.name])
            self.threads.add(thread)
            self.processes.add(
                CollectedProcess(ProcessId=msg.pid, ParentProcessId=msg.ppid)
            )

            nonlocal last_thread_info

            if (
                last_thread_info is not None
            ):  # XXX this will miss the very last one since we don't know when it ended
                (last_thread, start_instr) = last_thread_info
                self.thread_slices.add(
                    CollectedThreadSlice(
                        FirstInstructionCount=start_instr,
                        LastInstructionCount=msg.start_instr - 1,
                        Thread=last_thread,
                    )
                )
            last_thread = (thread, msg.start_instr)

        CollectFrom = {  # Field name -> parsing function
            "asid_libraries": CollectFrom_asid_libraries,
            "asid_info": CollectFrom_asid_info,
            "taint_flow": CollectFrom_taint_flow,
            "syscall": CollectFrom_syscall,
            "proc_trace": CollectFrom_proc_trace,
        }

        AttemptCounts = {k: 0 for k in CollectFrom}
        FailCounts = {k: 0 for k in CollectFrom}
        with PLogReader(self.pandalog) as plr:
            for msg in plr:
                for k in CollectFrom:
                    if hasfield(msg, k) and k not in self.skip_steps:
                        AttemptCounts[k] += 1
                        try:
                            CollectFrom[k](getattr(msg, k))
                        except Exception as e:
                            print("Warning: ", e)
                            FailCounts[k] += 1
                        break

        print(
            "Gathered {} Processes and {} Threads".format(
                len(self.processes), len(self.threads)
            )
        )
        for k in CollectFrom:
            print(
                "\t{} Attempts: {}, Failures: {}".format(
                    k, AttemptCounts[k], FailCounts[k]
                )
            )

    @time_log
    def CollectProcessMemoryMappings(self):
        # 2nd pass over plog
        #
        # This time to get mappings for processes
        print("Second pass over plog (Gathering Process Mappings)...")

        CollectedBetterMappings = set()
        self.CollectedBetterMappingRanges = {proc: {} for proc in self.processes}

        num_no_mappings = 0

        def CollectFrom_asid_libraries(entry, msg):
            nonlocal num_no_mappings
            if (msg.pid == 0) or (msg.ppid == 0) or (msg.tid == 0):
                num_no_mappings += 1
                return
            # thread = CollectedThread(
            #    ProcessId=msg.pid, ParentProcessId=msg.ppid, ThreadId=msg.tid, CreateTime=msg.create_time)
            process = CollectedProcess(ProcessId=msg.pid, ParentProcessId=msg.ppid)
            # mappings in this plog entry
            for mapping in msg.modules:
                better_mapping = BetterCollectedMapping(
                    AddressSpaceId=entry.asid,
                    Name=mapping.name,
                    File=mapping.file,
                    BaseAddress=mapping.base_addr,
                    Size=mapping.size,
                    Process=process,
                )
                CollectedBetterMappings.add(better_mapping)
                if better_mapping in self.CollectedBetterMappingRanges[process].keys():
                    (
                        FirstInstructionCount,
                        LastInstructionCount,
                    ) = self.CollectedBetterMappingRanges[process][better_mapping]
                    if entry.instr < FirstInstructionCount:
                        self.CollectedBetterMappingRanges[process][better_mapping] = (
                            entry.instr,
                            LastInstructionCount,
                        )
                    elif entry.instr > LastInstructionCount:
                        self.CollectedBetterMappingRanges[process][better_mapping] = (
                            FirstInstructionCount,
                            entry.instr,
                        )
                else:
                    self.CollectedBetterMappingRanges[process][better_mapping] = (
                        entry.instr,
                        entry.instr,
                    )

        CollectFrom = {
            "asid_libraries": CollectFrom_asid_libraries,
        }
        AttemptCounts = {k: 0 for k in CollectFrom}
        FailCounts = {k: 0 for k in CollectFrom}
        with PLogReader(self.pandalog) as plr:
            for msg in plr:
                for k in CollectFrom:
                    if hasfield(msg, k) and k not in self.skip_steps:
                        AttemptCounts[k] += 1
                        try:
                            CollectFrom[k](msg, getattr(msg, k))
                        except Exception as e:
                            print("Warning:", e)
                            FailCounts[k] += 1
                        break
        print(
            "Processed {} messages ({} without mapping)".format(
                sum(AttemptCounts[k] for k in AttemptCounts), num_no_mappings
            )
        )
        for k in CollectFrom:
            print(
                "\t{} Attempts: {}, Failures: {}".format(
                    k, AttemptCounts[k], FailCounts[k]
                )
            )
        print(
            "CollectedBetterMappingRanges Len {}".format(
                sum(
                    [
                        len(procmaps.keys())
                        for procmaps in self.CollectedBetterMappingRanges.values()
                    ]
                )
            )
        )

    @time_log
    def ConvertTaintFlowsToDatabase(self):
        print("Constructing db objects for Taint Flows and CodePoints")
        # TODO: do we need to return this dict?
        CollectedCodePointToDatabaseCodePoint = {}

        for tf in self.CollectedTaintFlows:
            src_thread = self.CollectedThreadToDatabaseThread[tf.SourceThread]
            src_mapping = self.CollectedMappingToDatabaseMapping[
                tf.SourceCodePoint.Mapping
            ]

            sink_thread = self.CollectedThreadToDatabaseThread[tf.SinkThread]
            sink_mapping = self.CollectedMappingToDatabaseMapping[
                tf.SinkCodePoint.Mapping
            ]

            CollectedCodePointToDatabaseCodePoint[tf] = self.ds.new_taintflow(
                tf.IsStore,
                src_thread,
                src_mapping,
                tf.SourceCodePoint.Offset,
                tf.SourceInstructionCount,
                sink_thread,
                sink_mapping,
                tf.SinkCodePoint.Offset,
                tf.SinkInstructionCount,
            )

    @time_log
    def ConvertSyscallsToDatabase(self):
        print("Constructing db objects for Syscalls")

        syscall_infos = []
        for s in self.CollectedSyscalls:
            args = []
            for a in s.Arguments:
                args.append({"name": a.Name, "type": a.Type, "value": a.Value})
            if s.Thread in self.CollectedThreadToDatabaseThread:
                syscall_infos.append((
                    self.CollectedThreadToDatabaseThread[s.Thread],
                    s.Name,
                    s.RetVal,
                    args,
                    s.InstructionCount,
                    s.ProgramCounter,
                ))

        self.ds.new_syscall_collection(syscall_infos)

    def CollectTaintFlowsAndSyscalls(self):
        print("Third pass over plog (Gathering Taint Flows and Syscalls)...")
        self.CollectedCodePoints = set()
        self.CollectedSyscalls = set()
        self.CollectedTaintFlows = set()
        # DuplicateTaintFlows = {}
        NoMappingCount = {
            "Source": 0,
            "Sink": 0,
        }

        def CollectFrom_syscall(entry, msg):
            SyscallFieldInfo = {
                "str": ("string", "{:s}"),
                "ptr": ("pointer", "0x{:x}"),
                "u64": ("unsigned64", "{:d}"),
                "u32": ("unsigned32", "{:d}"),
                "u16": ("unsigned16", "{:d}"),
                "i64": ("signed64", "{:d}"),
                "i32": ("signed32", "{:d}"),
                "i16": ("signed16", "{:d}"),
                "bytes_val": ("bytes", "{:d}"),
            }

            def syscall_arg_value(sarg):
                for fld, (typ, fmt) in SyscallFieldInfo.items():
                    if sarg.HasField(fld):
                        if fld == "bytes_val":
                            # TODO: do we need to strip out non-ascii for DB?
                            safe_str = getattr(sarg, fld)
                            return sarg.arg_name, typ, safe_str
                        return sarg.arg_name, typ, fmt.format(getattr(sarg, fld))
                assert False

            thread = CollectedThread(
                ProcessId=msg.pid,
                ParentProcessId=msg.ppid,
                ThreadId=msg.tid,
                CreateTime=msg.create_time,
            )
            self.CollectedSyscalls.add(
                CollectedSyscall(
                    Name=msg.call_name,
                    RetVal=msg.retcode,
                    Thread=thread,
                    InstructionCount=entry.instr,
                    Arguments=tuple(
                        CollectedSyscallArgument(*syscall_arg_value(arg))
                        for arg in msg.args
                    ),
                    ProgramCounter=entry.pc,
                )
            )
            return

        def CollectFrom_taint_flow(_, msg):
            source_thread = msg.source.cp.thread
            source_process = CollectedProcess(
                ProcessId=source_thread.pid, ParentProcessId=source_thread.ppid
            )
            source_thread = CollectedThread(
                ProcessId=source_thread.pid,
                ParentProcessId=source_thread.ppid,
                ThreadId=source_thread.tid,
                CreateTime=source_thread.create_time,
            )
            sink_thread = msg.sink.cp.thread
            sink_process = CollectedProcess(
                ProcessId=sink_thread.pid, ParentProcessId=sink_thread.ppid
            )
            sink_thread = CollectedThread(
                ProcessId=sink_thread.pid,
                ParentProcessId=sink_thread.ppid,
                ThreadId=sink_thread.tid,
                CreateTime=sink_thread.create_time,
            )

            # REQUIRES: CollectedBetterMappingRanges[{source,sink}_process].items() is sorted by ascending FirstInstructionCount
            # sink_mapping_slice = None
            sink_mapping, sink_offset = None, None
            for mapping, (
                FirstInstructionCount,
                LastInstructionCount,
            ) in self.CollectedBetterMappingRanges[sink_process].items():
                if (FirstInstructionCount <= msg.sink.instr) and (
                    LastInstructionCount >= msg.sink.instr
                ):
                    if (msg.sink.cp.pc >= mapping.BaseAddress) and (
                        msg.sink.cp.pc <= (mapping.BaseAddress + mapping.Size - 1)
                    ):
                        # sink_mapping_slice = ( FirstInstructionCount, LastInstructionCount)
                        sink_mapping = mapping
                        sink_offset = msg.sink.cp.pc - mapping.BaseAddress
                else:
                    if sink_mapping is not None:
                        break

            # source_mapping_slice = None # Unusued
            source_mapping, source_offset = None, None
            for mapping, (
                FirstInstructionCount,
                LastInstructionCount,
            ) in self.CollectedBetterMappingRanges[source_process].items():
                if (FirstInstructionCount <= msg.source.instr) and (
                    LastInstructionCount >= msg.source.instr
                ):
                    if (msg.source.cp.pc >= mapping.BaseAddress) and (
                        msg.source.cp.pc <= (mapping.BaseAddress + mapping.Size - 1)
                    ):
                        # source_mapping_slice = (FirstInstructionCount, LastInstructionCount)
                        source_mapping = mapping
                        source_offset = msg.source.cp.pc - mapping.BaseAddress
                else:
                    if source_mapping is not None:
                        break
            if sink_mapping is None:
                NoMappingCount["Sink"] += 1
            if source_mapping is None:
                NoMappingCount["Source"] += 1
            if (sink_mapping is None) or (source_mapping is None):
                return

            SourceCodePoint = CollectedCodePoint(
                Mapping=source_mapping, Offset=source_offset
            )
            SinkCodePoint = CollectedCodePoint(Mapping=sink_mapping, Offset=sink_offset)
            self.CollectedCodePoints.add(SourceCodePoint)
            self.CollectedCodePoints.add(SinkCodePoint)
            flow = CollectedTaintFlow(
                IsStore=msg.source.is_store,
                SourceCodePoint=SourceCodePoint,
                SourceThread=source_thread,
                SourceInstructionCount=msg.source.instr,
                SinkCodePoint=SinkCodePoint,
                SinkThread=sink_thread,
                SinkInstructionCount=msg.sink.instr,
            )
            # if flow in CollectedTaintFlows:
            #     if flow in DuplicateTaintFlows.keys():
            #         DuplicateTaintFlows[flow] += 1
            #     else:
            #         DuplicateTaintFlows[flow] = 2
            self.CollectedTaintFlows.add(flow)
            return

        CollectFrom = {
            "syscall": CollectFrom_syscall,
            "taint_flow": CollectFrom_taint_flow,
        }
        AttemptCounts = {k: 0 for k in CollectFrom}
        FailCounts = {k: 0 for k in CollectFrom}
        with PLogReader(self.pandalog) as plr:
            for msg in plr:
                for k in CollectFrom:
                    if hasfield(msg, k):
                        AttemptCounts[k] += 1
                        try:
                            CollectFrom[k](msg, getattr(msg, k))
                        except Exception as e:
                            FailCounts[k] += 1
                            print("Exception:", e)
                            raise e
                        break
        for k in CollectFrom:
            print(
                "\t{} Attempts: {}, Failures: {}".format(
                    k, AttemptCounts[k], FailCounts[k]
                )
            )
        print("\tNoMappingCount = {}".format(NoMappingCount))
        # print('\tDuplicate Flows {}'.format(len(DuplicateTaintFlows.keys())))
        # for flow, count in DuplicateTaintFlows.items():
        #     print('\t\tFlow Duplicated {} times: {}'.format(count, flow))
        #     if (flow.SourceCodePoint.Mapping.Name == 'toy_debug') and (flow.SinkCodePoint.Mapping.Name == 'toy_debug'):
        #         print('\t\t\tGhidra Flow Info: {:08x} -> {:08x}'.format(0x00100000 + flow.SourceCodePoint.Offset, 0x00100000 + flow.SinkCodePoint.Offset))

    def ConvertProcessThreadsMappingsToDatabase(self):
        print("Constructing db objects for thread, process, and mapping")
        # construct db process, and for each,
        # create associated threads and mappings and connect them up
        self.CollectedProcessToDatabaseProcess = {}
        self.CollectedThreadToDatabaseThread = {}
        self.CollectedMappingToDatabaseMapping = {}
        for p in self.processes:
            # Setting process create time to earliest thread. I think this is wrong.
            create_time = sys.maxsize
            for t in self.proc2threads[p]:
                if t.CreateTime < create_time:
                    create_time = t.CreateTime
            process = self.ds.new_process(
                self.execution, create_time, p.ProcessId, p.ParentProcessId
            )
            self.CollectedProcessToDatabaseProcess[p] = process

            for t in self.proc2threads[p]:
                if t in self.thread_names:
                    self.CollectedThreadToDatabaseThread[t] = self.ds.new_thread(
                        process, t.CreateTime, t.ThreadId, self.thread_names[t]
                    )

            for mapping, (
                FirstInstructionCount,
                LastInstructionCount,
            ) in self.CollectedBetterMappingRanges[p].items():
                self.CollectedMappingToDatabaseMapping[mapping] = self.ds.new_mapping(
                    process,
                    mapping.Name,
                    mapping.File,
                    mapping.AddressSpaceId,
                    mapping.BaseAddress,
                    FirstInstructionCount,
                    mapping.Size,
                    FirstInstructionCount,
                    LastInstructionCount,
                )

        if "threadslices" not in self.skip_steps:
            for thread_slice in self.thread_slices:
                self.ds.new_threadslice(
                    self.CollectedThreadToDatabaseThread[thread_slice.Thread],
                    thread_slice.FirstInstructionCount,
                    end_execution_offset=thread_slice.LastInstructionCount,
                )

    def CreateExecutionIfNeeded(self):
        matching_execution = self.ds.get_execution_by_name(self.exec_name)
        if matching_execution is None:
            matching_execution = self.ds.new_execution(self.exec_name)
        return matching_execution


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ingest pandalog and tranfer results to pandelephant"
    )
    parser.add_argument("-db_url", help="db url", action="store", required=True)
    parser.add_argument("-pandalog", help="pandalog", action="store", required=True)
    parser.add_argument(
        "-exec_name",
        "--exec-name",
        help="A name for the execution",
        action="store",
        required=True,
    )
    parser.add_argument(
        "-s",
        "--skip",
        action="append",
        help="Steps to skip. Valid values: " + " ".join(steps),
        required=False,
    )

    pargs = parser.parse_args()

    skips = []
    if pargs.skip:
        for arg in pargs.skip:
            if arg not in steps:
                raise ValueError(
                    f"Unable to skip step {arg}. Valid values are: {' '.join(steps)}"
                )
            skips.append(arg)

    print("%s %s" % (pargs.db_url, pargs.exec_name))
    PLogToPandelephant(pargs.pandalog, pargs.db_url, pargs.exec_name, skips)
