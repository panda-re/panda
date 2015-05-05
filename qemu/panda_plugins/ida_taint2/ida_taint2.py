#
# An IDA script to apply colors to instructions and functions based on taint
# and process introspection information in a pandalog
# Tested with IDA Pro 6.7
# Works in conjunction with PANDA on Windows 7 32-bit binaries
#
# Assumes everything (ida_taint2.bat, ida_taint2.py, pandalog_pb2.py, pandalog,
# binary) is in the same directory
#


import gzip
import idaapi as ida
import struct

import pandalog_pb2 as pl

RED    = 0x2020c0
ORANGE = 0x55aaff


def usage():
    usageStr = ( "ida_taint.py usage: <IDA program> -S\"ida_taint.py "
        "<pandalog file> <process name>\" <binary>" )
    print usageStr


def fatalError(errStr):
    idc.Warning(errStr)


def getArgs():
    if len(idc.ARGV) != 3:
        usage()
        errstr = ( "Error: invalid number of arguments to ida_taint.py.  "
            "ida_taint.py is now exiting..." )
        fatalError(errstr)
        return None
    return {'pandalogFileStr': idc.ARGV[1], 'processName': idc.ARGV[2]}


def parsePandalogFile(pandalogFileStr):
    entries = []
    try:
        with gzip.GzipFile(pandalogFileStr, 'rb') as f:
            while True:
                le = pl.LogEntry()
                sz = f.read(8)
                if not sz: break
                sz = struct.unpack("<Q", sz)[0]
                data = f.read(sz)
                le.ParseFromString(data)
                entries.append(le)
        return entries
    except:
        errstr = ( "Error: Pandalog file specified to ida_taint.py cannot "
            "be opened or parsed properly.  ida_taint.py is now exiting...\n" )
        fatalError(errstr)
        return None


def findProcessData(pandalog, processName):
    for entry in pandalog:
        if entry.HasField("new_pid") and entry.new_pid.name in processName:
            return {
                'virtual_program_base_address': entry.new_pid.virtual_base_addr,
                'pid': entry.new_pid.pid
            }
    errstr = ( "Error: data about specified process not found in pandalog file."
        "  ida_taint.py is now exiting..." )
    fatalError(errstr)
    return None


def rebaseProgramToDynamicBase(processBaseAddress):
    delta = processBaseAddress - ida.get_imagebase()
    rebaseStatus = idc.rebase_program(delta, MSF_FIXONCE)
    if rebaseStatus < 0:
        errstr = ( "Error: Problem rebasing program, error code {0}.  Check "
            "MOVE_SEGM_ error codes.  ida_taint.py is now exiting...\n" )
        fatalError(errstr.format(rebaseStatus))
        return -1
    return 0


def getTaintedPCs(pandalog, processName):
    taintedPCs = set()
    inDesiredProcess = False
    for entry in pandalog:
        if entry.HasField("new_pid") and entry.new_pid.name in processName:
            inDesiredProcess = True
        if entry.HasField("new_pid") and entry.new_pid.name not in processName:
            inDesiredProcess = False
        if (inDesiredProcess and entry.HasField("tainted_instr")
            and entry.tainted_instr and entry.pc < 0x80000000):
            taintedPCs.add(entry.pc)
    return taintedPCs


def annotateTaint(taintedProgramCounterList):
    for programCounter in iter(taintedProgramCounterList):
        SetColor(programCounter, CIC_ITEM, RED)
        functionBase = GetFunctionAttr(programCounter, FUNCATTR_START)
        if functionBase != 0xffffffff: # -1 doesn't work, probably a cast bug...
            SetColor(functionBase, CIC_FUNC, ORANGE)


def main():
    Wait() # for autoanalysis to finish
    print '\n\nida_taint2.py\n\n'

    args = getArgs()
    if args == None:
        return
    pandalog = parsePandalogFile(args['pandalogFileStr'])
    if pandalog == None:
        return
    processData = findProcessData(pandalog, args['processName'])
    if processData == None:
        return
    processBaseAddress = processData['virtual_program_base_address']
    infostr = ( "==== Annotating {0} ====\nPID: {1}\n"
        "Dynamic base address: {2:#x}\n" )
    print infostr.format(args['processName'],
        processData['pid'], processBaseAddress)
    rebaseStatus = rebaseProgramToDynamicBase(processBaseAddress)
    if rebaseStatus == -1:
        return
    taintedPCs = getTaintedPCs(pandalog, args['processName'])
    if taintedPCs == None:
        return
    annotateTaint(taintedPCs)
    print '\n\nida_taint2.py done\n\n'


if __name__ == '__main__':
    main()

