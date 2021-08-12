#!/usr/bin/python3
"""
Module for converting PANDAlog (plog) files to a pandelephant database. Run directly with:
    python -m pandare.PlogToPandelphant -db_url X -pandalog Y -exec_name Z
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

class PlogDispatcher:
    def __init__(self, pandalog, skip_steps=None):
        self.pandalog = pandalog
        self.skip_steps = skip_steps if skip_steps else []

    def dispatch(self, CollectFrom, collectTypes=False):
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
                            CollectFrom[k](self, msg, getattr(msg, k))
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

def _collect_thread_procs_from_asidlib(dispatcher, entry, msg):
    thread = collectedthread(
        processid=msg.pid,
        parentprocessid=msg.ppid,
        threadid=msg.tid,
        createtime=msg.create_time,
    )
    # there might be several names for a tid
    if thread in dispatcher.thread_names.keys():
        dispatcher.thread_names[thread].add(msg.proc_name)
    else:
        dispatcher.thread_names[thread] = set([msg.proc_name])
    dispatcher.threads.add(thread)
    dispatcher.processes.add(
        collectedprocess(processid=msg.pid, parentprocessid=msg.ppid)
    )

def _collect_thread_procs_from_asidinfo(dispatcher, entry, msg):
    for tid in msg.tids:
        thread = collectedthread(
            processid=msg.pid,
            parentprocessid=msg.ppid,
            threadid=tid,
            createtime=msg.create_time,
        )
        if thread in dispatcher.thread_names.keys():
            for name in msg.names:
                dispatcher.thread_names[thread].add(name)
        else:
            dispatcher.thread_names[thread] = set(msg.names)
        dispatcher.threads.add(thread)
        dispatcher.thread_slices.add(
            collectedthreadslice(
                firstinstructioncount=msg.start_instr,
                lastinstructioncount=msg.end_instr,
                thread=thread,
            )
        )
    dispatcher.processes.add(
        collectedprocess(processid=msg.pid, parentprocessid=msg.ppid)
    )

def _create_thread_procs_from_taintflow(dispatcher, entry, msg):
    source_thread = msg.source.cp.thread
    dispatcher.threads.add(
        collectedthread(
            processid=source_thread.pid,
            parentprocessid=source_thread.ppid,
            threadid=source_thread.tid,
            createtime=source_thread.create_time,
        )
    )
    dispatcher.processes.add(
        collectedprocess(
            ProcessId=source_thread.pid, ParentProcessId=source_thread.ppid
        )
    )
    sink_thread = msg.sink.cp.thread
    dispatcher.threads.add(
        CollectedThread(
            ProcessId=sink_thread.pid,
            ParentProcessId=sink_thread.ppid,
            ThreadId=sink_thread.tid,
            CreateTime=sink_thread.create_time,
        )
    )
    dispatcher.processes.add(
        CollectedProcess(
            ProcessId=sink_thread.pid, ParentProcessId=sink_thread.ppid
        )
    )

def _create_thread_procs_and_syscalls_from_syscall(dispatcher, entry, msg):
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

    # First update dispatcher.threads and dispatcher.processes with info from this syscall
    thread = CollectedThread(
        ProcessId=msg.pid,
        ParentProcessId=msg.ppid,
        ThreadId=msg.tid,
        CreateTime=msg.create_time,
    )

    dispatcher.threads.add(thread)
    dispatcher.processes.add(CollectedProcess(ProcessId=msg.pid, ParentProcessId=msg.ppid))

    # Then store info on this syscall in dispatcher.collectedSyscalls
    dispatcher.collectedSyscalls.add(
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

def _create_thread_procs_from_proctrace(dispatcher, _, msg):
    thread = CollectedThread(
        ProcessId=msg.pid,
        ParentProcessId=msg.ppid,
        ThreadId=msg.tid,
        CreateTime=msg.create_time,
    )
    if thread in dispatcher.thread_names.keys():
        dispatcher.thread_names[thread].add(msg.name)
    else:
        dispatcher.thread_names[thread] = set([msg.name])
    dispatcher.threads.add(thread)
    dispatcher.processes.add(
        CollectedProcess(ProcessId=msg.pid, ParentProcessId=msg.ppid)
    )

    if hasattr(dispatcher, 'last_thread_info') and dispatcher.last_thread_info is not None:
        # XXX this will miss the very last one since we don't know when it ended
        (last_thread, start_instr) = dispatcher.last_thread_info
        dispatcher.thread_slices.add(
            CollectedThreadSlice(
                FirstInstructionCount=start_instr,
                LastInstructionCount=msg.start_instr - 1,
                Thread=last_thread,
            )
        )

    dispatcher.last_thread_info = (thread, msg.start_instr)

def _collect_memmaps_from_asidlib(dispatcher, entry, msg):
    if (msg.pid == 0) or (msg.ppid == 0) or (msg.tid == 0):
        dispatcher.num_no_mappings += 1
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
        dispatcher.collectedBetterMappings.add(better_mapping)
        if better_mapping in dispatcher.collectedBetterMappingRanges[process].keys():
            (
                FirstInstructionCount,
                LastInstructionCount,
            ) = dispatcher.collectedBetterMappingRanges[process][better_mapping]
            if entry.instr < FirstInstructionCount:
                dispatcher.collectedBetterMappingRanges[process][better_mapping] = (
                    entry.instr,
                    LastInstructionCount,
                )
            elif entry.instr > LastInstructionCount:
                dispatcher.collectedBetterMappingRanges[process][better_mapping] = (
                    FirstInstructionCount,
                    entry.instr,
                )
        else:
            dispatcher.collectedBetterMappingRanges[process][better_mapping] = (
                entry.instr,
                entry.instr,
            )

def _collect_taint_flows(dispatcher, entry, msg):
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

    # REQUIRES: collectedBetterMappingRanges[{source,sink}_analyze].items() is sorted by ascending FirstInstructionCount
    # sink_mapping_slice = None
    sink_mapping, sink_offset = None, None
    for mapping, (
        FirstInstructionCount,
        LastInstructionCount,
    ) in dispatcher.collectedBetterMappingRanges[sink_analyze].items():
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
    ) in dispatcher.collectedBetterMappingRanges[source_analyze].items():
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
        dispatcher.NoMappingCount["Sink"] += 1
    if source_mapping is None:
        dispatcher.NoMappingCount["Source"] += 1
    if (sink_mapping is None) or (source_mapping is None):
        return

    SourceCodePoint = CollectedCodePoint(
        Mapping=source_mapping, Offset=source_offset
    )
    SinkCodePoint = CollectedCodePoint(Mapping=sink_mapping, Offset=sink_offset)
    dispatcher.collectedCodePoints.add(SourceCodePoint)
    dispatcher.collectedCodePoints.add(SinkCodePoint)
    flow = CollectedTaintFlow(
        IsStore=msg.source.is_store,
        SourceCodePoint=SourceCodePoint,
        SourceThread=source_thread,
        SourceInstructionCount=msg.source.instr,
        SinkCodePoint=SinkCodePoint,
        SinkThread=sink_thread,
        SinkInstructionCount=msg.sink.instr,
    )
    # if flow in collectedTaintFlows:
    #     if flow in DuplicateTaintFlows.keys():
    #         DuplicateTaintFlows[flow] += 1
    #     else:
    #         DuplicateTaintFlows[flow] = 2
    dispatcher.collectedTaintFlows.add(flow)


# End of dispatcher methods

def createExecutionIfNeeded(ds, exec_name):
    matching_execution = ds.get_execution_by_name(exec_name)
    if matching_execution is None:
        matching_execution = ds.new_execution(exec_name)
    return matching_execution



@time_log
def initialCollection(pandalog, skip_steps=None):
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
    dispatcher = PlogDispatcher(pandalog, skip_steps)
    dispatcher.processes = set()
    dispatcher.threads = set()
    dispatcher.thread_slices = set()
    dispatcher.thread_names = {}
    dispatcher.collectedSyscalls = set()

    types = dispatcher.dispatch({  # Field name -> parsing function
                "asid_libraries": _collect_thread_procs_from_asidlib,
                "asid_info":      _collect_thread_procs_from_asidinfo,
                "taint_flow":     _create_thread_procs_from_taintflow,
                "syscall":        _create_thread_procs_and_syscalls_from_syscall,
                "proc_trace":     _create_thread_procs_from_proctrace,
            }, collectTypes = True)

    print(f"Plog contains messages of types {types}")

    print(f"Gathered {len(dispatcher.processes)} Processes, {len(dispatcher.threads)} Threads"\
          f" and {len(dispatcher.collectedSyscalls)} syscalls")

    return dispatcher.processes, dispatcher.threads, dispatcher.thread_slices, \
           dispatcher.thread_names, dispatcher.collectedSyscalls, types

@time_log
def associateThreadsAndProcesses(threads, processes, thread_names, verbose=False):
    # associate threads and procs
    print("Associating Threads and Processes...")
    thread2proc = { # RETURN
        thread: CollectedProcess(
            ProcessId=thread.ProcessId, ParentProcessId=thread.ParentProcessId
        )
        for thread in threads
    }
    proc2threads = {proc: set() for proc in processes}
    for thread in threads:
        proc2threads[(thread.ProcessId, thread.ParentProcessId)].add(thread)
    # DuplicateCheck = set((thread.ThreadId, thread.CreateTime)
    #                     for thread in threads)

    # if len(DuplicateCheck) != len(thread2proc.keys()):
    #     raise Exception("Threads are not unique in (ThreadId, CreateTime)..."\
    #     "If you think this should be ingestable, change this line...")

    if verbose:
        for proc in proc2threads:
            print(f"Process (ProcessId {proc.ProcessId} ParentProcessId "\
                  f"{proc.ParentProcessId}) has {len(proc2threads[proc])} Threads")

            for thread in proc2threads[proc]:
                if thread in thread_names:
                    print(f"\tThread (ThreadId {thread.ThreadId} CreateTime "\
                          f"{thread.CreateTime:#x}) names: {thread_names[thread]}")

    return thread2proc, proc2threads

@time_log
def collectProcessMemoryMappings(pandalog, processes, skip_steps):
    # 2nd pass over plog
    # This time to get mappings for processes
    print("Second pass over plog (Gathering Process Mappings)...")

    dispatcher = PlogDispatcher(pandalog, skip_steps)
    dispatcher.collectedBetterMappings = set()
    dispatcher.collectedBetterMappingRanges = {proc: {} for proc in processes}
    dispatcher.num_no_mappings = 0

    dispatcher.dispatch({
        "asid_libraries": _collect_memmaps_from_asidlib,
    })

    print(f"{dispatcher.num_no_mappings} messages processed without mappings")

    mapping_len = sum([len(procmaps.keys())
                       for procmaps in dispatcher.collectedBetterMappingRanges.values()
                     ])
    print(f"collectedBetterMappingRanges Len {mapping_len}")

    return dispatcher.collectedBetterMappings, dispatcher.collectedBetterMappingRanges


@time_log
def collectTaintFlows():
    print("Third pass over plog (Gathering Taint Flows)...")

    dispatcher = PlogDispatcher(pandalog, skip_steps)

    dispatcher.collectedCodePoints = set()
    dispatcher.collectedTaintFlows = set()
    # DuplicateTaintFlows = {}
    dispatcher.NoMappingCount = {
        "Source": 0,
        "Sink": 0,
    }
    dispatcher.dispatch({
        "taint_flow": _collect_taint_flows,
    })

    print("\tNoMappingCount = {}".format(dispatcher.NoMappingCount))

    # print('\tDuplicate Flows {}'.format(len(DuplicateTaintFlows.keys())))
    # for flow, count in DuplicateTaintFlows.items():
    #     print('\t\tFlow Duplicated {} times: {}'.format(count, flow))
    #     if (flow.SourceCodePoint.Mapping.Name == 'toy_debug') and (flow.SinkCodePoint.Mapping.Name == 'toy_debug'):
    #         print('\t\t\tGhidra Flow Info: {:08x} -> {:08x}'.format(0x00100000 + flow.SourceCodePoint.Offset, 0x00100000 + flow.SinkCodePoint.Offset))

    print(
        "Collected {} Taint Flows {} Syscalls {} Code Points".format(
            len(dispatcher.collectedTaintFlows),
            len(dispatcher.collectedSyscalls),
            len(dispatcher.collectedCodePoints),
        )
    )

    return dispatcher.collectedCodePoints, dispatcher.collectedTaintFlows

@time_log
def convertProcessThreadsMappingsToDb(execution, ds, processes, proc2threads, thread_names, thread_slices,
                                            collectedBetterMappingRanges, skip_steps):
    print("Constructing db objects for thread, process, and mapping")
    # construct db process, and for each,
    # create associated threads and mappings and connect them up

    #CollectedProcessToDbProcess = {} # Unused
    collectedThreadToDbThread = {}
    collectedMappingToDbMapping = {}

    for p in processes:
        # Setting process create time to earliest thread. I think this is wrong.
        create_time = sys.maxsize
        for t in proc2threads[p]:
            if t.CreateTime < create_time:
                create_time = t.CreateTime
        process = ds.new_process(
            execution, create_time, p.ProcessId, p.ParentProcessId
        )
        #CollectedProcessToDbProcess[p] = process

        for t in proc2threads[p]:
            if t in thread_names:
                collectedThreadToDbThread[t] = ds.new_thread(
                    process, t.CreateTime, t.ThreadId, thread_names[t]
                )

        for mapping, (
            FirstInstructionCount,
            LastInstructionCount,
        ) in collectedBetterMappingRanges[p].items():
            collectedMappingToDbMapping[mapping] = ds.new_mapping(
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

    if "threadslices" not in skip_steps:
        for thread_slice in thread_slices:
            ds.new_threadslice(
                collectedThreadToDbThread[thread_slice.Thread],
                thread_slice.FirstInstructionCount,
                end_execution_offset=thread_slice.LastInstructionCount,
            )

    return collectedThreadToDbThread, collectedMappingToDbMapping

@time_log
def convertTaintFlowsToDb(ds, collectedTaintFlows, collectedThreadToDbThread, collectedMappingToDbMapping):
    print("Constructing db objects for Taint Flows and CodePoints")
    # TODO: do we need to return this dict? If not, why are we collecting it?
    #CollectedCodePointToDbCodePoint = {}

    for tf in collectedTaintFlows:
        src_thread = collectedThreadToDbThread[tf.SourceThread]
        src_mapping = collectedMappingToDbMapping[
            tf.SourceCodePoint.Mapping
        ]

        sink_thread = collectedThreadToDbThread[tf.SinkThread]
        sink_mapping = collectedMappingToDbMapping[
            tf.SinkCodePoint.Mapping
        ]

        #CollectedCodePointToDbCodePoint[tf] =
        ds.new_taintflow(
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
def convertSyscallsToDb(ds, collectedSyscalls, collectedThreadToDbThread):
    print("Constructing db objects for Syscalls")

    # Bulk insert items in chunks of 10k
    syscall_infos = []
    for idx, syscall in enumerate(collectedSyscalls):
        if idx > 0 and idx % 10000 == 0:
            ds.new_syscall_collection(syscall_infos)
            syscall_infos = []

        args = []
        for a in syscall.Arguments:
            args.append({"name": a.Name, "type": a.Type, "value": a.Value})
        if syscall.Thread in collectedThreadToDbThread:
            syscall_infos.append((
                collectedThreadToDbThread[syscall.Thread],
                syscall.Name,
                syscall.RetVal,
                args,
                syscall.InstructionCount,
                syscall.ProgramCounter,
            ))

    if len(syscall_infos):
        ds.new_syscall_collection(syscall_infos)



@time_log("Full import process")
def PLogToPandelephant(pandalog, db_url, exec_name, skip_steps=None, verbose=False):
    skip_steps = skip_steps if skip_steps else []

    ds = pandelephant.PandaDatastore(db_url)
    execution = createExecutionIfNeeded(ds, exec_name)

    # First pass over plog to determine threads, processes, syscalls, and plog message types
    processes, threads, thread_slices, thread_names, collectedSyscalls, plog_types = initialCollection(pandalog, skip_steps)

    # then associate threads to their processes.
    thread2proc, proc2threads = associateThreadsAndProcesses(threads, processes, thread_names, verbose)

    # Second pass over plog to determine memory mappings
    collectedBetterMappings, collectedBetterMappingRanges = collectProcessMemoryMappings(pandalog, processes, skip_steps)

    if verbose:
        # Report process/thread info and their mappings
        for proc in processes:
            print(
                "\tProcess (ProcessId {} ParentProcessId {}) has {} Threads {} Mappings".format(
                    proc.ProcessId,
                    proc.ParentProcessId,
                    len(proc2threads[proc]),
                    len(collectedBetterMappingRanges[proc].keys()),
                )
            )

            for mapping, (
                FirstInstructionCount,
                LastInstructionCount,
            ) in collectedBetterMappingRanges[proc].items():
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

    if "taint_flow" in plog_types:
        # Third pass over plog to determine taint flows
        collectedCodePoints, collectedTaintFlows = collectTaintFlows()
    else:
        collectedCodePoints = set()
        collectedTaintFlows = set()

    collectedThreadToDbThread, collectedMappingToDbMapping = convertProcessThreadsMappingsToDb(execution, ds, processes, proc2threads, thread_names, thread_slices, collectedBetterMappingRanges, skip_steps)

    if "taint_flow" in plog_types:
        convertTaintFlowsToDb(ds, collectedTaintFlows, collectedThreadToDbThread, collectedMappingToDbMapping)

    if "syscall" in plog_types:
        convertSyscallsToDb(ds, collectedSyscalls, collectedThreadToDbThread)

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
