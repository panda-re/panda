
# /* PANDABEGINCOMMENT
# * 
# * Authors:
# *  Tim Leek               tleek@ll.mit.edu
# *  Ryan Whelan            rwhelan@ll.mit.edu
# *  Joshua Hodosh          josh.hodosh@ll.mit.edu
# *  Michael Zhivich        mzhivich@ll.mit.edu
# *  Brendan Dolan-Gavitt   brendandg@gatech.edu
# * 
# * This work is licensed under the terms of the GNU GPL, version 2. 
# * See the COPYING file in the top-level directory. 
# * 
#PANDAENDCOMMENT */

"""
Output panda tool to parse system calls on Linux
"""

import re
import os
from collections import defaultdict
from sys import argv,exit

#arm_CALLNO = "env->regs[7]"
#arm_ARGS = ["env->regs[0]", "env->regs[1]", "env->regs[2]", "env->regs[3]", "env->regs[4]", "env->regs[5]", "env->regs[6]"]
#arm_SP = "env->regs[13]"
#arm_GUARD = "#ifdef TARGET_ARM"

#x86_CALLNO = "EAX"
#x86_ARGS = ["EBX", "ECX", "EDX", "ESI", "EDI", "EBP"]
#x86_SP = "ESP"
## Linux's syscall ABI doesn't change between IA32 and AMD64
#x86_GUARD = "#ifdef TARGET_I386"

def usage():
    print "Usage syscall_parser.py os arch"
    print "os can be linux or windows"
    print "arch can be x86 or arm"
    exit(1)

if len(argv) != 4:
    usage()

OS=argv[1]
ARCH=argv[2]

if not (OS == 'windows7' or OS == 'linux'):
    usage()

if not (ARCH == 'arm' or ARCH == 'x86'):
    usage()

print "os is [%s] arch is [%s]" % (OS, ARCH)

if ARCH=="x86":
    CALLNO="EAX"
    SP = "ESP" 
    GUARD = "#ifdef TARGET_I386" 

if ARCH=="arm":
    CALLNO = "env->regs[7]"
    SP = "env->regs[13]"
    GUARD = "#ifdef TARGET_ARM"

   
ARGS = ["arg0", "arg1", "arg2", "arg3", "arg4", "arg5", "arg6", "arg7", "arg8", "arg9", "arg10", "arg11", "arg12", "arg13", "arg14", "arg15"]



IDS="%s_%s" % (OS, ARCH)
PROTOS="%s_prototypes.txt" % IDS
MODE=ARCH
DESTDIR=argv[3]


#PROTOS = "android_arm_prototypes.txt" if len(argv) < 2 else argv[1]
#MODE = "ARM" if len(argv) < 3 else argv[2].upper()
#DESTDIR = "." if len(argv) < 4 else argv[3]



print "PROTOS = [%s]" % PROTOS
print "MODE = [%s]" % MODE
print "DESTDIR = [%s]" % DESTDIR


# TRL: I don't like this.
## set arch/OS specific args by mode
#for x in ["CALLNO", "ARGS", "SP", "GUARD"]:
#    locals()[x] = locals()["_".join([MODE, x])]

twoword_types = ["unsigned int", "unsigned long"]

types_64 = ["loff_t", 'u64']
stypes_32 = ["int", "long", '__s32', 'LONG']
types_32 = ["unsigned int", "unsigned long", "size_t", 'u32', 'off_t', 'timer_t', 'key_t', 
            'key_serial_t', 'mqd_t', 'clockid_t', 'aio_context_t', 'qid_t', 'old_sigset_t', 'union semun',
            'ULONG', 'SIZE_T', 'HANDLE', 'PBOOLEAN', 'PHANDLE', 'PLARGE_INTEGER', 'PLONG', 'PSIZE_T', 
            'PUCHAR', 'PULARGE_INTEGER', 'PULONG', 'PULONG_PTR', 'PUNICODE_STRING', 'PVOID', 'PWSTR']
types_16 = ['old_uid_t', 'uid_t', 'mode_t', 'gid_t', 'pid_t', 'USHORT']
types_pointer = ['cap_user_data_t', 'cap_user_header_t', '__sighandler_t', '...']


osarch = "%s_%s" % (OS, ARCH)

syscall_enter_switch = """

extern "C" {
#include "panda_plugin.h" 
}

#include "syscalls2.h" 
#include "panda_common.h"
#include "panda_plugin_plugin.h"

extern "C" {
#include "gen_syscalls_ext_typedefs_%s.h"   // osarch
#include "gen_syscall_ppp_register_enter_%s.cpp"  // osarch
}

#include "gen_syscall_ppp_boilerplate_enter_%s.cpp" // osarch

void syscall_enter_switch_%s ( CPUState *env, target_ulong pc ) {  // osarch
%s                                          // GUARD
    ReturnPoint rp;
    rp.ordinal = %s;                        // CALLNO
    rp.proc_id = panda_current_asid(env);
    rp.retaddr = calc_retaddr(env, pc);
    appendReturnPoint(rp);
    switch( %s ) {                          // CALLNO
""" % (osarch, osarch, osarch, osarch, GUARD, CALLNO, CALLNO)


syscall_return_switch = """

extern "C" {
#include "panda_plugin.h" 
}

#include "syscalls2.h" 
#include "panda_common.h"
#include "panda_plugin_plugin.h"

extern "C" {
#include "gen_syscalls_ext_typedefs_%s.h"   // osarch
#include "gen_syscall_ppp_register_return_%s.cpp"  // osarch
}

#include "gen_syscall_ppp_boilerplate_return_%s.cpp" // osarch

void syscall_return_switch_%s ( CPUState *env, target_ulong pc, target_ulong ordinal) {  // osarch
%s                                          // GUARD
    switch( ordinal ) {                          // CALLNO
""" % (osarch, osarch, osarch, osarch, GUARD)



def get_pointer(argnum):
    return "target_ulong arg%d = get_pointer(env, %d);\n" % (argnum, argnum)
    
def get_32(argnum):
    return "uint32_t arg%d = get_32(env, %d);\n" % (argnum, argnum)

def get_s32(argnum):
    return "int32_t arg%d = get_s32(env, %d);\n" % (argnum, argnum)

def get_64(argnum):
    return "uint64_t arg%d = get_64(env, %d);\n" % (argnum, argnum)

def get_return_pointer(argnum):
    return "target_ulong arg%d = get_return_pointer(env, %d);\n" % (argnum, argnum)
    
def get_return_32(argnum):
    return "uint32_t arg%d = get_return_32(env, %d);\n" % (argnum, argnum)

def get_return_s32(argnum):
    return "int32_t arg%d = get_return_s32(env, %d);\n" % (argnum, argnum)

def get_return_64(argnum):
    return "uint64_t arg%d = get_return_64(env, %d);\n" % (argnum, argnum)




CHAR_STAR = 'CHAR_STAR'
POINTER   = 'POINTER'
BYTES_8   = '8BYTE'
BYTES_4   = '4BYTE'
BYTES_2   = '2BYTE'
SIGNED_4  = '4SIGNED'
# C types for callback arguments
ARG_TYPE_C_TRANSLATIONS = { CHAR_STAR:  'target_ulong', # pointer
                            POINTER:    'target_ulong', # pointer
                            BYTES_8:    'uint64_t',
                            BYTES_4:    'uint32_t',
                            SIGNED_4:   'int32_t',
                            BYTES_2:    'uint16_t',
                          }

CPP_RESERVED = {"new": "anew", "data":"data_arg"}

NAMESPACE = "syscalls"

class Argument(object):
    def __init__(self):
        self._type = None
        self._name = None
        self.var  = None
    
    @property
    def type(self):
        return self._type
    
    @type.setter
    def type(self, newtype):
        assert(newtype in ARG_TYPE_C_TRANSLATIONS.keys())
        self._type = newtype
    
    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, newname):
        if newname.startswith('*'):
            newname = newname[1:]
        if newname in CPP_RESERVED:
            newname = CPP_RESERVED[newname]
        if newname is ')':
            newname = "fn"
        if newname.endswith('[]'):
            newname = newname[:-2]
        self._name = newname


class Syscall(object):
    def __init__(self, name):
        self.cxxargs = None
        self.cxx_std_fn = None
        self.cargs = None
        self.args = None
        self.name = name

# Typedefs for PPP C callbacks
typedefs = set()
# Names of all PPP C callbacks
cb_names_enter = set()
cb_names_return = set()

syscalls = [] # objects, having a set is useless for dedup

print PROTOS

# Goldfish kernel doesn't support OABI layer. Yay!
with open(PROTOS) as calls:
    linere = re.compile("(\d+) (.+) (\w+) ?\((.*)\);")
    charre = re.compile("char.*\*")
    for line in calls:
        # Fields: <no> <return-type> <name><signature with spaces>
        fields = linere.match(line)
        if fields is None:
            continue
        callno = fields.group(1)
        rettype = fields.group(2)
        callname = fields.group(3)
#        print "%s %s" % (callno, callname)
        args = fields.group(4).split(',')
        arg_types = []
        syscall_enter_switch += "// " + str(callno)+" "+ str(rettype)+" "+ str(callname)+" "+ str(args) + '\n'
        syscall_return_switch += "// " + str(callno)+" "+ str(rettype)+" "+ str(callname)+" "+ str(args) + '\n'
        for argno, arg in enumerate(args):
            # the .split() can leave us with args = ['']
            if arg == '':
                continue
            thisarg = Argument()
            arg = arg.strip()
            if arg.endswith('*') or len(arg.split()) == 1 or arg in twoword_types:
                # no argname, just type
                argname = "arg{0}".format(argno)
            else:
                argname = arg.split()[-1]
            thisarg.name = argname
            if argname == 'int':
                print "ERROR: shouldn't be naming arg 'int'! Arg text: '{0}'".format(arg)
                exit(1)
            if charre.search(arg) and not argname.endswith('buf') and argname != '...' and not argname.endswith('[]'):
                thisarg.type = CHAR_STAR
                arg_types.append(thisarg)
            elif '*' in arg or any([x in arg for x in types_pointer]):
                thisarg.type = POINTER
                arg_types.append(thisarg)
            elif any([x in arg for x in types_64]):
                thisarg.type = BYTES_8
                arg_types.append(thisarg)
            elif any([x in arg for x in types_32]) or any([x in arg for x in types_16]):
                thisarg.type = BYTES_4
                arg_types.append(thisarg)
            elif any([x in arg for x in stypes_32]) and 'unsigned' not in arg:
                thisarg.type = SIGNED_4
                arg_types.append(thisarg)
            elif arg == 'void':
                pass
            elif arg == 'unsigned' or (len(arg.split()) is 2 and arg.split()[0] == 'unsigned'):
                thisarg.type = BYTES_4
                arg_types.append(thisarg)
            else:
                if OS == 'windows7':
                    thisarg.type = BYTES_4
                    arg_types.append(thisarg)
                else:
                    print "huh? " + arg
                    syscall_enter_switch += "unknown: " + arg
                    syscall_return_switch += "unknown: " + arg

        syscall_enter_switch += "case " + callno + ": {\n"
        syscall_return_switch += "case " + callno + ": {\n"
        argno = 0
        for i, val in enumerate(arg_types):
            arg_type = val.type
            arg_name = val.name
            if argno >= len(ARGS):
#                alltext += "// out of registers. Use the stack!"+'\n'
                break
            if arg_type == CHAR_STAR:
                syscall_enter_switch += get_pointer(i)
                syscall_return_switch += get_return_pointer(i)
            elif arg_type == POINTER:
                syscall_enter_switch += get_pointer(i)
                syscall_return_switch += get_return_pointer(i)
            elif arg_type == BYTES_4:
                syscall_enter_switch += get_32(i)
                syscall_return_switch += get_return_32(i)
            elif arg_type == SIGNED_4:
                syscall_enter_switch += get_s32(i)
                syscall_return_switch += get_return_s32(i)
            elif arg_type == BYTES_8:
                # alignment sadness. Linux tried to make sure none of these happen
                if (argno % 2) == 1:
#                    alltext += "// skipping arg for alignment"+'\n'
                    argno+= 1
                    if argno >= len(ARGS):
#                        alltext += "// out of registers. Use the stack!"+'\n'
                        break
                syscall_enter_switch += get_64(i)
                syscall_return_switch += get_return_64(i)
                argno+=1
            argno+=1

        # each argument passed to C++ and C callbacks (the actual variable name or data)
            
        _c_args = ",".join(['env', 'pc'] + ["arg%d" % i for i in range(len(arg_types))])
        # declaration info (type and name) for each arg passed to C++ and C callbacks
        _c_args_types = ",".join(['CPUState* env', 'target_ulong pc'] + [ARG_TYPE_C_TRANSLATIONS[x.type] + " " + x.name for i, x in enumerate(arg_types)])
        typedef = "typedef void (*on_{0}_t)({1});".format(callname + "_enter", _c_args_types)
        typedefs.add(typedef)
        typedef = "typedef void (*on_{0}_t)({1});".format(callname + "_return", _c_args_types)
        typedefs.add(typedef )
        cb_names_enter.add("on_{0}".format(callname + "_enter"))
        cb_names_return.add("on_{0}".format(callname + "_return"))
        # prototype for the C++ callback (with arg types and names)
        syscall_enter_switch += "PPP_RUN_CB(on_{0}_enter, {1}) ; \n".format(callname, _c_args)
        syscall_enter_switch += "}; break;"+'\n'
        syscall_return_switch += "PPP_RUN_CB(on_{0}_return, {1}) ; \n".format(callname, _c_args)
        syscall_return_switch += "}; break;"+'\n'
       
    # The "all" and "unknown" callbacks
    syscall_enter_switch += "default:\n"
    syscall_enter_switch += "PPP_RUN_CB(on_unknown_sys_%s_%s_enter, env, pc, %s);\n" % (OS,ARCH, CALLNO)
    syscall_enter_switch += "}"+'\n'
    syscall_enter_switch += "PPP_RUN_CB(on_all_sys_%s_%s_enter, env, pc, %s);\n" % (OS,ARCH, CALLNO)
    typedefs.add("typedef void (*on_unknown_sys_%s_%s_enter_t)(CPUState *env, target_ulong pc, target_ulong callno);" % (OS,ARCH))
    typedefs.add("typedef void (*on_all_sys_%s_%s_enter_t)(CPUState *env, target_ulong pc, target_ulong callno);" % (OS,ARCH))
    cb_names_enter.add("on_unknown_sys_%s_%s_enter" % (OS,ARCH))
    cb_names_enter.add("on_all_sys_%s_%s_enter" % (OS,ARCH))

    syscall_return_switch += "default:\n"
    syscall_return_switch += "PPP_RUN_CB(on_unknown_sys_%s_%s_return, env, pc, %s);\n" % (OS,ARCH, CALLNO)
    syscall_return_switch += "}"+'\n'
    syscall_return_switch += "PPP_RUN_CB(on_all_sys_%s_%s_return, env, pc, %s);\n" % (OS,ARCH, CALLNO)
    typedefs.add("typedef void (*on_unknown_sys_%s_%s_return_t)(CPUState *env, target_ulong pc, target_ulong callno);" % (OS,ARCH))
    typedefs.add("typedef void (*on_all_sys_%s_%s_return_t)(CPUState *env, target_ulong pc, target_ulong callno);" % (OS,ARCH))
    cb_names_return.add("on_unknown_sys_%s_%s_return" % (OS,ARCH))
    cb_names_return.add("on_all_sys_%s_%s_return" % (OS,ARCH))

syscall_return_switch += "#endif\n } \n"
syscall_enter_switch += "#endif\n } \n"

with open(os.path.join(DESTDIR, "gen_syscalls_ext_typedefs_%s.h" % IDS), "w") as callbacktypes:
    callbacktypes.write(GUARD + "\n")
    for t in typedefs:
        callbacktypes.write(t+"\n")
    callbacktypes.write("#endif\n")

with open(os.path.join(DESTDIR, "gen_syscall_switch_enter_%s.cpp" % IDS), "w") as dispatchfile:
    dispatchfile.write(syscall_enter_switch)
with open(os.path.join(DESTDIR, "gen_syscall_switch_return_%s.cpp" % IDS), "w") as dispatchfile:
    dispatchfile.write(syscall_return_switch)

with open(os.path.join(DESTDIR, "gen_syscall_ppp_register_enter_%s.cpp" % IDS), "w") as pppfile:
    pppfile.write(GUARD + "\n")
    for ppp in cb_names_enter:
        pppfile.write("PPP_PROT_REG_CB({0})\n".format(ppp))
    pppfile.write("#endif\n")

with open(os.path.join(DESTDIR, "gen_syscall_ppp_register_return_%s.cpp" % IDS), "w") as pppfile:
    pppfile.write(GUARD + "\n")
    for ppp in cb_names_return:
        pppfile.write("PPP_PROT_REG_CB({0})\n".format(ppp))
    pppfile.write("#endif\n")


with open(os.path.join(DESTDIR, "gen_syscall_ppp_boilerplate_enter_%s.cpp" % IDS), "w") as pppfile:
    pppfile.write(GUARD + "\n")
    for ppp in cb_names_enter:
        pppfile.write("PPP_CB_BOILERPLATE({0})\n".format(ppp))
    pppfile.write("#endif\n")

with open(os.path.join(DESTDIR, "gen_syscall_ppp_boilerplate_return_%s.cpp" % IDS), "w") as pppfile:
    pppfile.write(GUARD + "\n")
    for ppp in cb_names_return:
        pppfile.write("PPP_CB_BOILERPLATE({0})\n".format(ppp))
    pppfile.write("#endif\n")
