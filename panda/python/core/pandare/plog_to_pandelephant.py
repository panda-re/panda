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
    def __init__(self, pandalog, db_url, exec_name, skip_steps=None, verbose=False):
        self.pandalog = pandalog
        self.db_url = db_url
        self.exec_name = exec_name
        self.skip_steps = skip_steps if skip_steps else []
        self.verbose = verbose

        self.ds = pandelephant.PandaDatastore(db_url)
        self.execution = self.CreateExecutionIfNeeded()

        # First pass over plog to determine threads, processes, syscalls, and plog message types
        plog_types = self.InitialCollection()
        # then associate threads to their processes.
        self.AssociateThreadsAndProcesses()

        # Second pass over plog to determine memory mappings
        self.CollectProcessMemoryMappings()

        if "taint_flow" in plog_types:
            # Third pass over plog to determine taint flows
            self.CollectTaintFlows()

        self.ConvertProcessThreadsMappingsToDatabase()

        if "taint_flow" in plog_types:
            self.ConvertTaintFlowsToDatabase()

        if "syscall" in plog_types:
            self.ConvertSyscallsToDatabase()

        # // init

    def _plog_dispatcher(self, CollectFrom, collectTypes=False):
        '''
        Enumeate through the PandaLog. For each entry, check if it is of any type
        which has a key in CollectFrom. If so, call the provided function

        For example, calling plog_dispatcher({'foo': self.foo})
        will call the function self.foo for every message in the pandalog of type foo
        self.foo will take be called with two arguments: msg and msg['foo']
        '''
        AttemptCounts = {k: 0 for k in CollectFrom}
        FailCounts = {k: 0 for k in CollectFrom}

        msgTypes = set()

        with PLogReader(self.pandalog) as plr:
            for msg in plr:
                for k in CollectFrom:
                    if hasfield(msg, k) and k not in self.skip_steps:
                        if collectTypes:
                            msgTypes.add(k)

                        AttemptCounts[k] += 1
                        try:
                            CollectFrom[k](msg, getattr(msg, k))
                        except Exception as e:
                            print("Warning:", e)
                            #raise
                            FailCounts[k] += 1
                        break

        for k in CollectFrom:
            print(
                "\t{} Attempts: {}, Failures: {}".format(
                    k, AttemptCounts[k], FailCounts[k]
                )
            )

        return list(msgTypes)

    @time_log
    def InitialCollection(self):
        """
        Do a first pass over the pandalog to gather basic information on:
            1) Threads
            2) Proceses
            3) Syscalls

        This first pass has no dependencies.

        It's essential that we get *all* the threads and processes that could possibly
        be referenced in subsequent analyses - to ensure we're not missing any, we examine
        messgaes of every type and create threads/processes whenever we see a new one referenced.
        
        In theory proc_trace should have info for all processes (and maybe threads?) but
        if we fail to populate an item in self.processes/self.threads here and subsequently
        try to report information on it, we'll run into errors.

        Why don't we just gather these on the fly? Because there are multiple sources
        for this information and they have to be reconciled. It's oddly tricky to
        get a consistent view out of a replay of the set of threads and processes and
        their names.
        """

        print("First pass over plog (Gathering Processes and Threads)...")

        # thread is (pid, ppid, tid, create_time)
        # process is (pid, ppid)
        self.processes = set()
        self.threads = set()
        self.thread_slices = set()
        self.thread_names = {}
        self.CollectedSyscalls = set()

        types = self._plog_dispatcher({  # Field name -> parsing function
                    "asid_libraries": self._collect_thread_procs_from_asidlib,
                    "asid_info":      self._collect_thread_procs_from_asidinfo,
                    "taint_flow":     self._create_thread_procs_from_taintflow,
                    "syscall":        self._create_thread_procs_and_syscalls_from_syscall,
                    "proc_trace":     self._create_thread_procs_from_proctrace,
                }, collectTypes = True)

        print(f"Plog contains messages of types {types}")

        print(f"Gathered {len(self.processes)} Processes, {len(self.threads)} Threads"\
              f" and {len(self.CollectedSyscalls)} syscalls")

        return types

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
        # DuplicateCheck = set((thread.ThreadId, thread.CreateTime)
        #                     for thread in self.threads)

        # if len(DuplicateCheck) != len(self.thread2proc.keys()):
        #     raise Exception("Threads are not unique in (ThreadId, CreateTime)..."\
        #     "If you think this should be ingestable, change this line...")

        if self.verbose:
            for proc in self.proc2threads:
                print(f"Process (ProcessId {proc.ProcessId} ParentProcessId "\
                      f"{proc.ParentProcessId}) has {len(self.proc2threads[proc])} Threads")

                for thread in self.proc2threads[proc]:
                    if thread in self.thread_names:
                        print(f"\tThread (ThreadId {thread.ThreadId} CreateTime "\
                              f"{thread.CreateTime:#x}) names: {self.thread_names[thread]}")

    @time_log
    def CollectProcessMemoryMappings(self):
        # 2nd pass over plog
        # This time to get mappings for processes
        print("Second pass over plog (Gathering Process Mappings)...")

        self.CollectedBetterMappings = set()
        self.CollectedBetterMappingRanges = {proc: {} for proc in self.processes}
        self.num_no_mappings = 0

        self._plog_dispatcher({
                "asid_libraries": self._collect_memmaps_from_asidlib,
            })

        print(f"{self.num_no_mappings} messages processed without mappings")

        mapping_len = sum([len(procmaps.keys())
                           for procmaps in self.CollectedBetterMappingRanges.values()
                         ])
        print(f"CollectedBetterMappingRanges Len {mapping_len}")

        if self.verbose:
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

    @time_log
    def CollectTaintFlows(self):
        print("Third pass over plog (Gathering Taint Flows)...")
        self.CollectedCodePoints = set()
        self.CollectedTaintFlows = set()
        # DuplicateTaintFlows = {}
        self.NoMappingCount = {
            "Source": 0,
            "Sink": 0,
        }

        self._plog_dispatcher({
                "taint_flow": self._collect_taint_flows,
            })

        print("\tNoMappingCount = {}".format(self.NoMappingCount))

        # print('\tDuplicate Flows {}'.format(len(DuplicateTaintFlows.keys())))
        # for flow, count in DuplicateTaintFlows.items():
        #     print('\t\tFlow Duplicated {} times: {}'.format(count, flow))
        #     if (flow.SourceCodePoint.Mapping.Name == 'toy_debug') and (flow.SinkCodePoint.Mapping.Name == 'toy_debug'):
        #         print('\t\t\tGhidra Flow Info: {:08x} -> {:08x}'.format(0x00100000 + flow.SourceCodePoint.Offset, 0x00100000 + flow.SinkCodePoint.Offset))

        print(
            "Collected {} Taint Flows {} Syscalls {} Code Points".format(
                len(self.CollectedTaintFlows),
                len(self.CollectedSyscalls),
                len(self.CollectedCodePoints),
            )
        )

    @time_log
    def ConvertTaintFlowsToDatabase(self):
        print("Constructing db objects for Taint Flows and CodePoints")
        # TODO: do we need to return this dict? If not, why are we collecting it?
        #CollectedCodePointToDatabaseCodePoint = {}

        for tf in self.CollectedTaintFlows:
            src_thread = self.CollectedThreadToDatabaseThread[tf.SourceThread]
            src_mapping = self.CollectedMappingToDatabaseMapping[
                tf.SourceCodePoint.Mapping
            ]

            sink_thread = self.CollectedThreadToDatabaseThread[tf.SinkThread]
            sink_mapping = self.CollectedMappingToDatabaseMapping[
                tf.SinkCodePoint.Mapping
            ]

            #CollectedCodePointToDatabaseCodePoint[tf] =
            self.ds.new_taintflow(
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

        # Bulk insert items in chunks of 10k
        syscall_infos = []
        for idx, syscall in enumerate(self.CollectedSyscalls):
            if idx > 0 and idx % 10000 == 0:
                self.ds.new_syscall_collection(syscall_infos)
                syscall_infos = []

            args = []
            for a in syscall.Arguments:
                args.append({"name": a.Name, "type": a.Type, "value": a.Value})
            if syscall.Thread in self.CollectedThreadToDatabaseThread:
                syscall_infos.append((
                    self.CollectedThreadToDatabaseThread[syscall.Thread],
                    syscall.Name,
                    syscall.RetVal,
                    args,
                    syscall.InstructionCount,
                    syscall.ProgramCounter,
                ))

        if len(syscall_infos):
            self.ds.new_syscall_collection(syscall_infos)

    @time_log
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

    def _collect_thread_procs_from_asidlib(self, _, msg):
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

    def _collect_memmaps_from_asidlib(self, entry, msg):
        if (msg.pid == 0) or (msg.ppid == 0) or (msg.tid == 0):
            self.num_no_mappings += 1
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
            self.CollectedBetterMappings.add(better_mapping)
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


    def _collect_thread_procs_from_asidinfo(self, _, msg):
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

    def _create_thread_procs_from_taintflow(self, _, msg):
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

    def _collect_taint_flows(self, _, msg):
        source_thread = msg.source.cp.thread
        source_analyze = CollectedProcess(
            ProcessId=source_thread.pid, ParentProcessId=source_thread.ppid
        )
        source_thread = CollectedThread(
            ProcessId=source_thread.pid,
            ParentProcessId=source_thread.ppid,
            ThreadId=source_thread.tid,
            CreateTime=source_thread.create_time,
        )
        sink_thread = msg.sink.cp.thread
        sink_analyze = CollectedProcess(
            ProcessId=sink_thread.pid, ParentProcessId=sink_thread.ppid
        )
        sink_thread = CollectedThread(
            ProcessId=sink_thread.pid,
            ParentProcessId=sink_thread.ppid,
            ThreadId=sink_thread.tid,
            CreateTime=sink_thread.create_time,
        )

        # REQUIRES: CollectedBetterMappingRanges[{source,sink}_analyze].items() is sorted by ascending FirstInstructionCount
        # sink_mapping_slice = None
        sink_mapping, sink_offset = None, None
        for mapping, (
            FirstInstructionCount,
            LastInstructionCount,
        ) in self.CollectedBetterMappingRanges[sink_analyze].items():
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
        ) in self.CollectedBetterMappingRanges[source_analyze].items():
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
            self.NoMappingCount["Sink"] += 1
        if source_mapping is None:
            self.NoMappingCount["Source"] += 1
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

    def _create_thread_procs_and_syscalls_from_syscall(self, entry, msg):
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
            # Failed to return - invalid argument
            raise ValueError(f"Unsuported argument type {sarg}")

        # First update self.threads and self.processes with info from this syscall
        thread = CollectedThread(
            ProcessId=msg.pid,
            ParentProcessId=msg.ppid,
            ThreadId=msg.tid,
            CreateTime=msg.create_time,
        )

        self.threads.add(thread)
        self.processes.add(CollectedProcess(ProcessId=msg.pid, ParentProcessId=msg.ppid))

        # Then store info on this syscall in self.CollectedSyscalls
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

    def _create_thread_procs_from_proctrace(self, _, msg):
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

        if hasattr(self, 'last_thread_info') and self.last_thread_info is not None:
            # XXX this will miss the very last one since we don't know when it ended
            (last_thread, start_instr) = self.last_thread_info
            self.thread_slices.add(
                CollectedThreadSlice(
                    FirstInstructionCount=start_instr,
                    LastInstructionCount=msg.start_instr - 1,
                    Thread=last_thread,
                )
            )

        self.last_thread_info = (thread, msg.start_instr)




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
    parser.add_argument("-v", help="verbose mode", action="store_true")

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
    PLogToPandelephant(pargs.pandalog, pargs.db_url, pargs.exec_name, skips, pargs.v)
