#!/usr/bin/python3
from datetime import datetime, timedelta
import argparse
import sys
import time
import os
import collections

# Assumes you've installed pandelephant package with setup.py
import pandelephant

# PLogReader from pandare package is easiest to import,
# but if it's unavailable, fallback to searching PYTHONPATH
# which users should add panda/panda/scripts to
try:
    from plog_reader import PLogReader
except ImportError:
    try:
        from pandare.plog_reader import PLogReader
    except ImportError:
        import PLogReader
    except ImportError:
        print("Unable to locate PLogReader")
        sys.exit(-1)

"""
USAGE: plog_to_pandelephant.py db_url plog
"""

DEBUG_VERBOSE = False

# HasField will raise an exception if that isnt a possible field name
# so this version translates that into a False
def hasfield(msg, field_name):
    try:
        if msg.HasField(field_name):
            return True
        else:
            return False
    except:
        return False

CollectedThread = collections.namedtuple('CollectedThread', ['ProcessId', 'ParentProcessId', 'ThreadId', 'CreateTime'])
CollectedProcess = collections.namedtuple('CollectedProcess', ['ProcessId', 'ParentProcessId'])
CollectedThreadSlice = collections.namedtuple('CollectedThreadSlice', ['FirstInstructionCount', 'LastInstructionCount', 'Thread'])
CollectedMappingSlice = collections.namedtuple('CollectedMappingSlice', ['InstructionCount', 'AddressSpaceId', 'Mappings'])
CollectedMapping = collections.namedtuple('CollectedMapping', ['Name', 'File', 'BaseAddress', 'Size'])
BetterCollectedMapping = collections.namedtuple('BetterCollectedMapping', ['AddressSpaceId', 'Process', 'Name', 'File', 'BaseAddress', 'Size'])
CollectedCodePoint = collections.namedtuple('CollectedCodePoint', ['Mapping', 'Offset'])
CollectedSyscall = collections.namedtuple('CollectedSyscall', ['Name', 'RetVal', 'Thread', 'InstructionCount', 'Arguments'])
CollectedSyscallArgument = collections.namedtuple('CollectedSyscallArgument', ['Name', 'Type', 'Value'])
CollectedTaintFlow = collections.namedtuple('CollectedTaintFlow', ['IsStore', 'SourceCodePoint', 'SourceThread', 'SourceInstructionCount', 'SinkCodePoint', 'SinkThread', 'SinkInstructionCount'])

def CollectThreadsAndProcesses(pandalog):
    # Why don't we just gather these on the fly?
    # Because there are multiple sources for this information
    # and they have to be reconciled.
    # It's oddly tricky to get a consistent view out of a replay
    # of the set of threads and processes and their names.
    # One could check at every basic block (by invoking Osi)
    # but that would be very slow.  So we check at a few std
    # temporal points (syscall, every 100 bb, asid_info logging points)
    # and reconcile.
    # Better would be if we had callback on after-scheduler-changes-proc
    #  s.t. we could obtain proc/thread.

    # thread is (pid, ppid, tid, create_time)
    # process is (pid, ppid)
    processes = set()
    threads = set()
    thread_slices = set()
    thread_names = {}
    def CollectFrom_asid_libraries(msg):
        thread = CollectedThread(ProcessId=msg.pid, ParentProcessId=msg.ppid, ThreadId=msg.tid, CreateTime=msg.create_time)
        # there might be several names for a tid
        if thread in thread_names.keys():
            thread_names[thread].add(msg.proc_name)
        else:
            thread_names[thread] = set([msg.proc_name])
        threads.add(thread)
        processes.add(CollectedProcess(ProcessId=msg.pid, ParentProcessId=msg.ppid))
    def CollectFrom_asid_info(msg):
        for tid in msg.tids:
            thread = CollectedThread(ProcessId=msg.pid, ParentProcessId=msg.ppid, ThreadId=tid, CreateTime=msg.create_time)
            if thread in thread_names.keys():
                for name in msg.names:
                    thread_names[thread].add(name)
            else:
                thread_names[thread] = set(msg.names)
            threads.add(thread)
            thread_slices.add(CollectedThreadSlice(FirstInstructionCount=msg.start_instr, LastInstructionCount=msg.end_instr, Thread=thread))
        processes.add(CollectedProcess(ProcessId=msg.pid, ParentProcessId=msg.ppid))
    def CollectFrom_taint_flow(msg):
        source_thread = msg.source.cp.thread
        threads.add(CollectedThread(ProcessId=source_thread.pid, ParentProcessId=source_thread.ppid, ThreadId=source_thread.tid, CreateTime=source_thread.create_time))
        processes.add(CollectedProcess(ProcessId=source_thread.pid, ParentProcessId=source_thread.ppid))
        sink_thread = msg.sink.cp.thread
        threads.add(CollectedThread(ProcessId=sink_thread.pid, ParentProcessId=sink_thread.ppid, ThreadId=sink_thread.tid, CreateTime=sink_thread.create_time))
        processes.add(CollectedProcess(ProcessId=sink_thread.pid, ParentProcessId=sink_thread.ppid))
    def CollectFrom_syscall(msg):
        threads.add(CollectedThread(ProcessId=msg.pid, ParentProcessId=msg.ppid, ThreadId=msg.tid, CreateTime=msg.create_time))
        processes.add(CollectedProcess(ProcessId=msg.pid, ParentProcessId=msg.ppid))

    CollectFrom = {
        'asid_libraries': CollectFrom_asid_libraries,
        'asid_info': CollectFrom_asid_info,
        'taint_flow': CollectFrom_taint_flow,
        'syscall': CollectFrom_syscall,
    }

    AttemptCounts = { k: 0 for k in CollectFrom.keys() }
    FailCounts = { k: 0 for k in CollectFrom.keys() }
    with PLogReader(pandalog) as plr:
        for msg in plr:
            for k in CollectFrom.keys():
                if hasfield(msg, k):
                    AttemptCounts[k] += 1
                    try:
                        CollectFrom[k](getattr(msg, k))
                    except Exception as e:
                        print("Warning: ", e)
                        FailCounts[k] += 1
                        pass
                    break
    print('Gathered {} Processes and {} Threads'.format(len(processes), len(threads)))
    for k in CollectFrom.keys():
        print('\t{} Attempts: {}, Failures: {}'.format(k, AttemptCounts[k], FailCounts[k]))
    return processes, threads, thread_names, thread_slices

def AssociateThreadsAndProcesses(processes, threads, thread_names):
    # associate threads and procs
    thread2proc = { thread: CollectedProcess(ProcessId=thread.ProcessId, ParentProcessId=thread.ParentProcessId) for thread in threads }
    proc2threads = { proc: set() for proc in processes }
    newthreads = set([]) # All threads observed
    DuplicateCheck = set((thread.ThreadId, thread.CreateTime) for thread in threads)
    for thread in threads:
        proc2threads[(thread.ProcessId, thread.ParentProcessId)].add(thread)
    if len(DuplicateCheck) != len(thread2proc.keys()):
        raise Exception("Threads are not unique in (ThreadId, CreateTime)... If you think this should be ingestable, change this line...")

    for proc in proc2threads.keys():
        print('Process (ProcessId {} ParentProcessId {}) has {} Threads'.format(proc.ProcessId, proc.ParentProcessId, len(proc2threads[proc])))
        for thread in proc2threads[proc]:
            print('\tThread (ThreadId {} CreateTime {:#x}) names: {}'.format(thread.ThreadId, thread.CreateTime, thread_names[thread]))

    return proc2threads, thread2proc

def CollectProcessMemoryMappings(pandalog, processes):
    # 2nd pass over plog
    #
    # This time to get mappings for processes

    CollectedBetterMappings = set()
    CollectedBetterMappingRanges = { proc: { } for proc in processes }

    num_no_mappings = 0
    def CollectFrom_asid_libraries(entry, msg):
        nonlocal num_no_mappings
        if (msg.pid == 0) or (msg.ppid == 0) or (msg.tid == 0):
            num_no_mappings += 1
            return
        thread = CollectedThread(ProcessId=msg.pid, ParentProcessId=msg.ppid, ThreadId=msg.tid, CreateTime=msg.create_time)
        process = CollectedProcess(ProcessId=msg.pid, ParentProcessId=msg.ppid)
        # mappings in this plog entry
        for mapping in msg.modules:
            better_mapping = BetterCollectedMapping(AddressSpaceId=entry.asid, Name=mapping.name, File=mapping.file, BaseAddress=mapping.base_addr, Size=mapping.size, Process=process)
            CollectedBetterMappings.add(better_mapping)
            if better_mapping in CollectedBetterMappingRanges[process].keys():
                FirstInstructionCount, LastInstructionCount = CollectedBetterMappingRanges[process][better_mapping]
                if entry.instr < FirstInstructionCount:
                    CollectedBetterMappingRanges[process][better_mapping] = (entry.instr, LastInstructionCount)
                elif entry.instr > LastInstructionCount:
                    CollectedBetterMappingRanges[process][better_mapping] = (FirstInstructionCount, entry.instr)
            else:
                CollectedBetterMappingRanges[process][better_mapping] = (entry.instr, entry.instr)

    CollectFrom = {
        'asid_libraries': CollectFrom_asid_libraries,
    }
    AttemptCounts = { k: 0 for k in CollectFrom.keys() }
    FailCounts = { k: 0 for k in CollectFrom.keys() }
    with PLogReader(pandalog) as plr:
        for msg in plr:
            for k in CollectFrom.keys():
                if hasfield(msg, k):
                    AttemptCounts[k] += 1
                    try:
                        CollectFrom[k](msg, getattr(msg, k))
                    except Exception as e:
                        print("Warning:", e)
                        FailCounts[k] += 1
                        pass
                    break
    print('Processed {} messages ({} without mapping)'.format(sum(AttemptCounts[k] for k in AttemptCounts.keys()), num_no_mappings))
    for k in CollectFrom.keys():
        print('\t{} Attempts: {}, Failures: {}'.format(k, AttemptCounts[k], FailCounts[k]))
    print('CollectedBetterMappingRanges Len {}'.format(sum(len(procmaps.keys()) for procmaps in CollectedBetterMappingRanges.values())))
    return CollectedBetterMappingRanges

def ConvertTaintFlowsAndSyscallsToDatabase(datastore, CollectedSyscalls, CollectedTaintFlows, CollectedCodePoints, processes, CollectedThreadToDatabaseThread, CollectedMappingToDatabaseMapping):
    CollectedCodePointToDatabaseCodePoint = {}
    CollectedSyscallToDatabaseSyscall = {}
    for s in CollectedSyscalls:
        args = []
        for a in s.Arguments:
            args.append({'name': a.Name, 'type': a.Type, 'value': a.Value})
        if s.Thread in CollectedThreadToDatabaseThread:
            CollectedSyscallToDatabaseSyscall[s] = datastore.new_syscall(CollectedThreadToDatabaseThread[s.Thread], s.Name, s.RetVal, args, s.InstructionCount)

    for tf in CollectedTaintFlows:
        src_thread = CollectedThreadToDatabaseThread[tf.SourceThread]
        src_mapping = CollectedMappingToDatabaseMapping[tf.SourceCodePoint.Mapping]

        sink_thread = CollectedThreadToDatabaseThread[tf.SinkThread]
        sink_mapping = CollectedMappingToDatabaseMapping[tf.SinkCodePoint.Mapping]

        CollectedCodePointToDatabaseCodePoint[tf] = datastore.new_taintflow(tf.IsStore, src_thread, src_mapping, tf.SourceCodePoint.Offset, tf.SourceInstructionCount, sink_thread, sink_mapping, tf.SinkCodePoint.Offset, tf.SinkInstructionCount)


def CollectTaintFlowsAndSyscalls(pandalog, CollectedBetterMappingRanges):
    CollectedCodePoints = set()
    CollectedSyscalls = set()
    CollectedTaintFlows = set()
    # DuplicateTaintFlows = {}
    NoMappingCount = {
        'Source': 0,
        'Sink': 0,
    }
    def CollectFrom_syscall(entry, msg):
        args = []
        SyscallFieldInfo = {
            'str': ('string',      '{:s}'),
            'ptr': ('pointer',     '0x{:x}'),
            'u64': ('unsigned64', '{:d}'),
            'u32': ('unsigned32', '{:d}'),
            'u16': ('unsigned16', '{:d}'),
            'i64': ('signed64',   '{:d}'),
            'i32': ('signed32',   '{:d}'),
            'i16': ('signed16',   '{:d}'),
        }
        def syscall_arg_value(arg):
            for fld, (typ, fmt) in SyscallFieldInfo.items():
                if arg.HasField(fld):
                    return arg.arg_name, typ, fmt.format(getattr(arg, fld))
            assert(False)
        thread = CollectedThread(ProcessId=msg.pid, ParentProcessId=msg.ppid, ThreadId=msg.tid, CreateTime=msg.create_time)
        CollectedSyscalls.add(CollectedSyscall(
            Name=msg.call_name,
            RetVal=msg.retcode,
            Thread=thread,
            InstructionCount=entry.instr,
            Arguments=tuple(
                CollectedSyscallArgument(*syscall_arg_value(arg))
                for arg in msg.args
            )
        ))
        return
    def CollectFrom_taint_flow(entry, msg):
        source_thread = msg.source.cp.thread
        source_process = CollectedProcess(ProcessId=source_thread.pid, ParentProcessId=source_thread.ppid)
        source_thread = CollectedThread(ProcessId=source_thread.pid, ParentProcessId=source_thread.ppid, ThreadId=source_thread.tid, CreateTime=source_thread.create_time)
        sink_thread = msg.sink.cp.thread
        sink_process = CollectedProcess(ProcessId=sink_thread.pid, ParentProcessId=sink_thread.ppid)
        sink_thread = CollectedThread(ProcessId=sink_thread.pid, ParentProcessId=sink_thread.ppid, ThreadId=sink_thread.tid, CreateTime=sink_thread.create_time)

        # REQUIRES: CollectedBetterMappingRanges[{source,sink}_process].items() is sorted by ascending FirstInstructionCount
        sink_mapping_slice, sink_mapping, sink_offset = None, None, None
        for mapping, (FirstInstructionCount, LastInstructionCount) in CollectedBetterMappingRanges[sink_process].items():
            if (FirstInstructionCount <= msg.sink.instr) and (LastInstructionCount >= msg.sink.instr):
                if (msg.sink.cp.pc >= mapping.BaseAddress) and (msg.sink.cp.pc <= (mapping.BaseAddress + mapping.Size - 1)):
                    sink_mapping_slice = (FirstInstructionCount, LastInstructionCount)
                    sink_mapping = mapping
                    sink_offset = msg.sink.cp.pc - mapping.BaseAddress
            else:
                if not (sink_mapping is None):
                    break

        source_mapping_slice, source_mapping, source_offset = None, None, None
        for mapping, (FirstInstructionCount, LastInstructionCount) in CollectedBetterMappingRanges[source_process].items():
            if (FirstInstructionCount <= msg.source.instr) and (LastInstructionCount >= msg.source.instr):
                if (msg.source.cp.pc >= mapping.BaseAddress) and (msg.source.cp.pc <= (mapping.BaseAddress + mapping.Size - 1)):
                    source_mapping_slice = (FirstInstructionCount, LastInstructionCount)
                    source_mapping = mapping
                    source_offset = msg.source.cp.pc - mapping.BaseAddress
            else:
                if not (source_mapping is None):
                    break
        if sink_mapping is None:
            NoMappingCount['Sink'] += 1
        if source_mapping is None:
            NoMappingCount['Source'] += 1
        if (sink_mapping is None) or (source_mapping is None):
            return

        SourceCodePoint = CollectedCodePoint(Mapping=source_mapping, Offset=source_offset)
        SinkCodePoint = CollectedCodePoint(Mapping=sink_mapping, Offset=sink_offset)
        CollectedCodePoints.add(SourceCodePoint)
        CollectedCodePoints.add(SinkCodePoint)
        flow = CollectedTaintFlow(
            IsStore=msg.source.is_store,
            SourceCodePoint=SourceCodePoint, SourceThread=source_thread, SourceInstructionCount=msg.source.instr,
            SinkCodePoint=SinkCodePoint, SinkThread=sink_thread, SinkInstructionCount=msg.sink.instr
        )
        # if flow in CollectedTaintFlows:
        #     if flow in DuplicateTaintFlows.keys():
        #         DuplicateTaintFlows[flow] += 1
        #     else:
        #         DuplicateTaintFlows[flow] = 2
        CollectedTaintFlows.add(flow)
        return
    CollectFrom = {
        'syscall': CollectFrom_syscall,
        'taint_flow': CollectFrom_taint_flow,
    }
    AttemptCounts = { k: 0 for k in CollectFrom.keys() }
    FailCounts = { k: 0 for k in CollectFrom.keys() }
    with PLogReader(pandalog) as plr:
        for msg in plr:
            for k in CollectFrom.keys():
                if hasfield(msg, k):
                    AttemptCounts[k] += 1
                    try:
                        CollectFrom[k](msg, getattr(msg, k))
                    except Exception as e:
                        FailCounts[k] += 1
                    break
    for k in CollectFrom.keys():
        print('\t{} Attempts: {}, Failures: {}'.format(k, AttemptCounts[k], FailCounts[k]))
    print('\tNoMappingCount = {}'.format(NoMappingCount))
    # print('\tDuplicate Flows {}'.format(len(DuplicateTaintFlows.keys())))
    # for flow, count in DuplicateTaintFlows.items():
    #     print('\t\tFlow Duplicated {} times: {}'.format(count, flow))
    #     if (flow.SourceCodePoint.Mapping.Name == 'toy_debug') and (flow.SinkCodePoint.Mapping.Name == 'toy_debug'):
    #         print('\t\t\tGhidra Flow Info: {:08x} -> {:08x}'.format(0x00100000 + flow.SourceCodePoint.Offset, 0x00100000 + flow.SinkCodePoint.Offset))
    return CollectedTaintFlows, CollectedSyscalls, CollectedCodePoints

def ConvertProcessThreadsMappingsToDatabase(datastore, execution, processes, threads, CollectedBetterMappingRanges, thread_names, proc2threads, thread_slices):
    # construct db process, and for each,
    # create associated threads and mappings and connect them up
    CollectedProcessToDatabaseProcess = {}
    CollectedThreadToDatabaseThread = {}
    CollectedMappingToDatabaseMapping = {}
    for p in processes:
        # Setting process create time to earliest thread. I think this is wrong.
        create_time = sys.maxsize
        for t in proc2threads[p]:
            if t.CreateTime < create_time:
                create_time = t.CreateTime
        process = datastore.new_process(execution, create_time, p.ProcessId, p.ParentProcessId)
        CollectedProcessToDatabaseProcess[p] = process

        for t in proc2threads[p]:
            if t in thread_names:
                CollectedThreadToDatabaseThread[t] = datastore.new_thread(process, t.CreateTime, t.ThreadId, thread_names[t])
        
        for mapping, (FirstInstructionCount, LastInstructionCount) in CollectedBetterMappingRanges[p].items():
            CollectedMappingToDatabaseMapping[mapping] = datastore.new_mapping(process, mapping.Name, mapping.File, mapping.AddressSpaceId, mapping.BaseAddress, FirstInstructionCount, mapping.Size, FirstInstructionCount, LastInstructionCount)

    for thread_slice in thread_slices:
        datastore.new_threadslice(CollectedThreadToDatabaseThread[thread_slice.Thread], thread_slice.FirstInstructionCount, end_execution_offset=thread_slice.LastInstructionCount)

    return CollectedProcessToDatabaseProcess, CollectedThreadToDatabaseThread, CollectedMappingToDatabaseMapping

def CreateExecutionIfNeeded(datastore, exec_name):
    matching_execution = datastore.get_execution_by_name(exec_name)
    if matching_execution is None:
        matching_execution = datastore.new_execution(exec_name)
    return matching_execution

def plog_to_pe(pandalog,  db_url, exec_name):
    start_time = time.time()
    ds = pandelephant.PandaDatastore(db_url)

    execution = CreateExecutionIfNeeded(datastore=ds, exec_name=exec_name)

    print("First pass over plog (Gathering Processes and Threads)...")
    t1 = time.time()
    processes, threads, thread_names, thread_slices = CollectThreadsAndProcesses(pandalog)
    t2 = time.time()
    print ("{:.2f} sec for 1st pass".format(t2 - t1))

    print('Associating Threads and Processes...')
    t3 = time.time()
    proc2threads, thread2proc = AssociateThreadsAndProcesses(processes, threads, thread_names)
    t4 = time.time()
    print ("{:.2f} sec for association".format(t4 - t3))

    print("Second pass over plog (Gathering Process Mappings)...")
    t5 = time.time()
    # mappings, CollectedBetterMappingRanges = CollectProcessMemoryMappings(pandalog, processes)
    CollectedBetterMappingRanges = CollectProcessMemoryMappings(pandalog, processes)
    t6 = time.time()
    print ("{:.2f} sec for mapping gathering".format(t6 - t5))

    print('Got {} BetterMappings...'.format(sum(len(procmaps.keys()) for procmaps in CollectedBetterMappingRanges.values())))
    for proc in processes:
        print('\tProcess (ProcessId {} ParentProcessId {}) has {} Threads {} Mappings'.format(proc.ProcessId, proc.ParentProcessId, len(proc2threads[proc]), len(CollectedBetterMappingRanges[proc].keys())))
        for mapping, (FirstInstructionCount, LastInstructionCount) in CollectedBetterMappingRanges[proc].items():
            print('\t\tFrom Instruction {} - {} in Address Space {:#x} Mapping {} File {} BaseAddress {:#x} Size {:#x}'.format(
                FirstInstructionCount,
                LastInstructionCount,
                mapping.AddressSpaceId,
                mapping.Name,
                mapping.File,
                mapping.BaseAddress,
                mapping.Size
            ))

    print('Third pass over plog (Gathering Taint Flows and Syscalls)...')
    t7 = time.time()
    CollectedTaintFlows, CollectedSyscalls, CollectedCodePoints = CollectTaintFlowsAndSyscalls(pandalog, CollectedBetterMappingRanges)
    t8 = time.time()
    print('{:.2f} sec to collect Taint Flows and Syscalls...'.format(t8 - t7))
    print('Collected {} Taint Flows {} Syscalls {} Code Points'.format(len(CollectedTaintFlows), len(CollectedSyscalls), len(CollectedCodePoints)))

    print("Constructing db objects for thread, process, and mapping")
    t9 = time.time()
    CollectedProcessToDatabaseProcess, CollectedThreadToDatabaseThread, CollectedMappingToDatabaseMapping = ConvertProcessThreadsMappingsToDatabase(ds, execution, processes, threads, CollectedBetterMappingRanges, thread_names, proc2threads, thread_slices)
    t10 = time.time()
    print ("{:.2f} sec for db objects creation".format(t10 - t9))

    print("Constructing db objects for Taint Flows, Syscalls, and CodePoints")
    t11 = time.time()
    ConvertTaintFlowsAndSyscallsToDatabase(ds, CollectedSyscalls, CollectedTaintFlows, CollectedCodePoints, processes, CollectedThreadToDatabaseThread, CollectedMappingToDatabaseMapping)
    t12 = time.time()
    print ("{:.2f} sec for db objects create/commit".format(t12 - t11))


    print("final time: %.2f sec" % (time.time() - start_time))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ingest pandalog and tranfer results to pandelephant")
    parser.add_argument("-db_url", help="db url", action="store", required=True)
    parser.add_argument("-pandalog", help="pandalog", action="store", required=True)
    parser.add_argument("-exec_name", "--exec-name", help="A name for the execution", action="store", required=True)

    args = parser.parse_args()

    print("%s %s" % (args.db_url, args.exec_name))
    plog_to_pe(args.pandalog, args.db_url, args.exec_name)
