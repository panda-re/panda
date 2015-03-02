#
# An IDA script to apply colors to instructions and functions based on taint
# information
# Tested with IDA Pro 6.7
#


import idaapi as ida
import json


RED    = 0x2020c0
ORANGE = 0x55aaff


def usage():
    usageStr = ( "ida_taint.py usage: <IDA program> -S\"ida_taint.py "
        "<JSON file> <process name>\" <binary>" )
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
    return {'jsonFileStr': idc.ARGV[1], 'processName': idc.ARGV[2]}


def openJsonFile(jsonFileStr):
    try:
        jsonFileHandle = open(jsonFileStr, "r")
        return jsonFileHandle
    except:
        errstr = ( "Error: JSON file specified to ida_taint.py cannot "
            "be opened.  ida_taint.py is now exiting...\n" )
        fatalError(errstr)
        return None


def parseJsonFile(jsonFileHandle):
    try:
        taintJsonObject = json.load(jsonFileHandle)
        return taintJsonObject
    except:
        errstr = ( "Error: JSON file parsing error.  "
            "ida_taint.py is now exiting...\n" )
        fatalError(errstr)
        return None


def findProcessData(taintJsonObject, processName):
    for i in range(len(taintJsonObject)):
        if taintJsonObject[i]['process_name'] in processName:
            return taintJsonObject[i]
    errstr = ( "Error: data about specified process not found in JSON file."
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


def getTaintedPCs(taintJsonObject, processName):
    taintedPCs = []
    for i in range(len(taintJsonObject)):
        addr = taintJsonObject[i]['virtual_program_address']
        if (taintJsonObject[i]['process_name'] in processName) \
                and (addr < 0x80000000):
            taintedPCs.append(taintJsonObject[i]['virtual_program_address'])
    return taintedPCs


def annotateTaint(taintedProgramCounterList):
    for programCounter in iter(taintedProgramCounterList):
        SetColor(programCounter, CIC_ITEM, RED)
        functionBase = GetFunctionAttr(programCounter, FUNCATTR_START)
        if functionBase != 0xffffffff: # -1 doesn't work, probably a cast bug...
            SetColor(functionBase, CIC_FUNC, ORANGE)


def main():
    Wait() # for autoanalysis to finish
    print '\n\nida_taint.py\n\n'

    args = getArgs()
    if args == None:
        return
    jsonHandle = openJsonFile(args['jsonFileStr'])
    if jsonHandle == None:
        return
    taintJsonObject = parseJsonFile(jsonHandle)
    jsonHandle.close()
    if taintJsonObject == None:
        return
    processData = findProcessData(taintJsonObject, args['processName'])
    if processData == None:
        return
    processBaseAddress = processData['virtual_program_base_address']
    infostr = ( "==== Annotating {0} ====\nASID: {1:#x}\nPID: {2}\n"
        "Dynamic base address: {3:#x}\n" )
    print infostr.format(args['processName'], processData['asid'],
        processData['pid'], processBaseAddress)
    rebaseStatus = rebaseProgramToDynamicBase(processBaseAddress)
    if rebaseStatus == -1:
        return
    taintedPCs = getTaintedPCs(taintJsonObject, args['processName'])
    if taintedPCs == None:
        return
    annotateTaint(taintedPCs)
    print '\n\nida_taint.py done\n\n'


if __name__ == '__main__':
    main()

