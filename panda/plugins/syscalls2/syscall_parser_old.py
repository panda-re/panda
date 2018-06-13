#!/usr/bin/env python2.7
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

KNOWN_OS = set(["linux", "windows_7", "windows_xpsp2", "windows_xpsp3"])
arch32 = set(['x86', 'arm'])

def usage():
    print "Usage syscall_parser.py <destdir> <os> <arch> [<os> <arch> ...]"
    print "os can be", " or ".join(KNOWN_OS)
    print "arch can be x86 or arm"
    exit(1)

if len(argv[2:]) % 2 != 0:
    usage()

DESTDIR = argv[1]
if not os.path.isdir(DESTDIR):
    usage()

# Typedefs and names for PPP C callbacks
# We want these to be global so that we don't get duplicate
# definitions when multiple OSes implement a system call with the
# same name & semantics (if it has the same name but different
# semantics, you should rename it in the prototypes file!)
typedefs = defaultdict(set)
cb_names_enter = defaultdict(set)
cb_names_return = defaultdict(set)

# Common to every OS, so we put them here
# A little goofy, but we use #if 1 as the keyname because it will
# be pasted verbatim into the file later
typedefs['#if 1'].add("typedef void (*on_unknown_sys_enter_t)(CPUState *cpu, target_ulong pc, target_ulong callno);")
typedefs['#if 1'].add("typedef void (*on_all_sys_enter_t)(CPUState *cpu, target_ulong pc, target_ulong callno);")
cb_names_enter['#if 1'].add("on_unknown_sys_enter")
cb_names_enter['#if 1'].add("on_all_sys_enter")
typedefs['#if 1'].add("typedef void (*on_unknown_sys_return_t)(CPUState *cpu, target_ulong pc, target_ulong callno);")
typedefs['#if 1'].add("typedef void (*on_all_sys_return_t)(CPUState *cpu, target_ulong pc, target_ulong callno);")
cb_names_return['#if 1'].add("on_unknown_sys_return")
cb_names_return['#if 1'].add("on_all_sys_return")

for OS, ARCH in zip(argv[2::2], argv[3::2]):
    if OS not in KNOWN_OS:
        usage()

    if not (ARCH == 'arm' or ARCH == 'x86'):
        usage()

    print "os is [%s] arch is [%s]" % (OS, ARCH)

    if ARCH=="x86":
        CALLNO="env->regs[R_EAX]"
        SP = "env->regs[R_ESP]"
        GUARD = "#ifdef TARGET_I386"

    if ARCH=="arm":
        CALLNO = "env->regs[7]"
        SP = "env->regs[13]"
        GUARD = "#ifdef TARGET_ARM"


    osarch = "%s_%s" % (OS, ARCH)
    PROTOS = "prototypes/%s_prototypes.txt" % osarch
    MODE=ARCH


    print "PROTOS = [%s]" % PROTOS
    print "MODE = [%s]" % MODE
    print "DESTDIR = [%s]" % DESTDIR


    twoword_types = ["unsigned int", "unsigned long"]

    types_64 = ["loff_t", 'u64']
    stypes_32 = ["int", "long", '__s32', 'LONG']
    types_32 = ["unsigned int", "unsigned long", "size_t", 'u32', 'off_t', 'timer_t', 'key_t',
                'key_serial_t', 'mqd_t', 'clockid_t', 'aio_context_t', 'qid_t', 'old_sigset_t', 'union semun',
                'ULONG', 'SIZE_T', 'HANDLE', 'PBOOLEAN', 'PHANDLE', 'PLARGE_INTEGER', 'PLONG', 'PSIZE_T',
                'PUCHAR', 'PULARGE_INTEGER', 'PULONG', 'PULONG_PTR', 'PUNICODE_STRING', 'PVOID', 'PWSTR']
    types_16 = ['old_uid_t', 'uid_t', 'mode_t', 'gid_t', 'pid_t', 'USHORT']
    types_pointer = ['cap_user_data_t', 'cap_user_header_t', '__sighandler_t', '...']

    syscall_enter_switch = """
#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "syscalls2.h"
#include "syscalls_common.h"

extern "C" {
#include "gen_syscalls_ext_typedefs.h"
#include "gen_syscall_ppp_extern_enter.h"
#include "gen_syscall_ppp_extern_return.h"
}

void syscall_enter_switch_%s ( CPUState *cpu, target_ulong pc ) {  // osarch
%s                                          // GUARD
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    ReturnPoint rp;
    rp.ordinal = %s;                        // CALLNO
    rp.proc_id = panda_current_asid(cpu);
    rp.retaddr = calc_retaddr(cpu, pc);
    switch( %s ) {                          // CALLNO
""" % (osarch, GUARD, CALLNO, CALLNO)


    syscall_return_switch = """
#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "syscalls2.h"
#include "syscalls_common.h"

extern "C" {
#include "gen_syscalls_ext_typedefs.h"
#include "gen_syscall_ppp_extern_return.h"
}

void syscall_return_switch_%s ( CPUState *cpu, target_ulong pc, target_ulong ordinal, ReturnPoint &rp) {  // osarch
%s                                          // GUARD
    //CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    switch( ordinal ) {                          // CALLNO
""" % (osarch, GUARD)





    CHAR_STAR = 'CHAR_STAR'
    POINTER   = 'POINTER'
    BYTES_8   = '8BYTE'
    BYTES_4   = '4BYTE'
    BYTES_2   = '2BYTE'
    SIGNED_4  = '4SIGNED'
    # C types for callback arguments
    ARG_TYPE_C_TRANSLATIONS = { CHAR_STAR:  'uint32_t' if ARCH in arch32 else 'uint64_t', # pointer
                                POINTER:    'uint32_t' if ARCH in arch32 else 'uint64_t', # pointer
                                BYTES_8:    'uint64_t',
                                BYTES_4:    'uint32_t',
                                SIGNED_4:   'int32_t',
                                BYTES_2:    'uint16_t',
                              }

    CPP_RESERVED = {"new": "anew", "data":"data_arg"}

    # Functions to emit the code that gets the nth syscall argument of a
    # given type.
    def get_pointer(argnum):
        return get_32(argnum) if ARCH in arch32 else get_64(argnum)

    def get_32(argnum):
        return "uint32_t arg%d = get_32(cpu, %d);\n" % (argnum, argnum)

    def get_s32(argnum):
        return "int32_t arg%d = get_s32(cpu, %d);\n" % (argnum, argnum)

    def get_64(argnum):
        return "uint64_t arg%d = get_64(cpu, %d);\n" % (argnum, argnum)

    def get_return_pointer(argnum):
        return "target_ulong arg%d = get_return_pointer(cpu, %d);\n" % (argnum, argnum)

    def get_return_32(argnum):
        return "uint32_t arg%d = get_return_32(cpu, %d);\n" % (argnum, argnum)

    def get_return_s32(argnum):
        return "int32_t arg%d = get_return_s32(cpu, %d);\n" % (argnum, argnum)

    def get_return_64(argnum):
        return "uint64_t arg%d = get_return_64(cpu, %d);\n" % (argnum, argnum)

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
                elif '*' in arg or any([x in arg for x in types_pointer]) or argname.endswith('[]'):
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
                    # Warn but assume it's a 32-bit argument
                    print "Warning: %s not of known type, assuming 32-bit" % arg
                    thisarg.type = BYTES_4
                    arg_types.append(thisarg)

            syscall_enter_switch += "case " + callno + ": {\n"
            syscall_return_switch += "case " + callno + ": {\n"
            argno = 0
            for i, val in enumerate(arg_types):
                arg_type = val.type
                arg_name = val.name
                if arg_type == CHAR_STAR:
                    syscall_enter_switch += get_pointer(i)
                elif arg_type == POINTER:
                    syscall_enter_switch += get_pointer(i)
                elif arg_type == BYTES_4:
                    syscall_enter_switch += get_32(i)
                elif arg_type == SIGNED_4:
                    syscall_enter_switch += get_s32(i)
                elif arg_type == BYTES_8:
                    # alignment sadness. Linux tried to make sure none of these happen
                    if (argno % 2) == 1:
                        argno+= 1
                    syscall_enter_switch += get_64(i)
                    argno+=1
                argno+=1

            # each argument passed to C++ and C callbacks (the actual variable name or data)

            _c_args = ",".join(['cpu', 'pc'] + ["arg%d" % i for i in range(len(arg_types))])
            # declaration info (type and name) for each arg passed to C++ and C callbacks
            def fixname(name):
                if name == "cpu": return "cpu_fixed"
                else: return name

            _c_args_types = ",".join(['CPUState* cpu', 'target_ulong pc'] + [ARG_TYPE_C_TRANSLATIONS[x.type] + " " + fixname(x.name) for x in arg_types])
            typedef = "typedef void (*on_{0}_t)({1});".format(callname + "_enter", _c_args_types)
            typedefs[GUARD].add(typedef)
            typedef = "typedef void (*on_{0}_t)({1});".format(callname + "_return", _c_args_types)
            typedefs[GUARD].add(typedef )
            cb_names_enter[GUARD].add("on_{0}".format(callname + "_enter"))
            cb_names_return[GUARD].add("on_{0}".format(callname + "_return"))
            # Marshal the args into the ReturnPoint for use at the return site
            # Note: not a typo; we want to check if anyone is listening for the
            # *return* before doing the memcpys in to the ReturnPoint
            syscall_enter_switch += "if (PPP_CHECK_CB(on_{0}_return)) {{\n".format(callname)
            for i, x in enumerate(arg_types):
                syscall_enter_switch += "memcpy(rp.params[{0}], &arg{0}, sizeof({1}));\n".format(i, ARG_TYPE_C_TRANSLATIONS[x.type])
            syscall_enter_switch += "}\n"
            # Unmarshal the args from the ReturnPoint
            for i, x in enumerate(arg_types):
                syscall_return_switch += "%s arg%d;\n" % (ARG_TYPE_C_TRANSLATIONS[x.type], i)
            syscall_return_switch += "if (PPP_CHECK_CB(on_{0}_return)) {{\n".format(callname)
            for i, x in enumerate(arg_types):
                syscall_return_switch += "memcpy(&arg%d, rp.params[%d], sizeof(%s));\n" % (i, i, ARG_TYPE_C_TRANSLATIONS[x.type])
            syscall_return_switch += "}\n"
            # prototype for the C++ callback (with arg types and names)
            syscall_enter_switch += "PPP_RUN_CB(on_{0}_enter, {1}) ; \n".format(callname, _c_args)
            syscall_enter_switch += "}; break;"+'\n'
            syscall_return_switch += "PPP_RUN_CB(on_{0}_return, {1}) ; \n".format(callname, _c_args)
            syscall_return_switch += "}; break;"+'\n'

        # The "all" and "unknown" callbacks
        syscall_enter_switch += "default:\n"
        syscall_enter_switch += "PPP_RUN_CB(on_unknown_sys_enter, cpu, pc, %s);\n" % CALLNO
        syscall_enter_switch += "}"+'\n'
        syscall_enter_switch += "PPP_RUN_CB(on_all_sys_enter, cpu, pc, %s);\n" % CALLNO
        syscall_enter_switch += "appendReturnPoint(rp);\n"

        syscall_return_switch += "default:\n"
        syscall_return_switch += "PPP_RUN_CB(on_unknown_sys_return, cpu, pc, rp.ordinal);\n"
        syscall_return_switch += "}"+'\n'
        syscall_return_switch += "PPP_RUN_CB(on_all_sys_return, cpu, pc, rp.ordinal);\n"

    syscall_return_switch += "#endif\n } \n"
    syscall_enter_switch += "#endif\n } \n"

    with open(os.path.join(DESTDIR, "gen_syscall_switch_enter_%s.cpp" % osarch), "w") as dispatchfile:
        print "Writing", "gen_syscall_switch_enter_%s.cpp" % osarch
        dispatchfile.write(syscall_enter_switch)
    with open(os.path.join(DESTDIR, "gen_syscall_switch_return_%s.cpp" % osarch), "w") as dispatchfile:
        print "Writing", "gen_syscall_switch_return_%s.cpp" % osarch
        dispatchfile.write(syscall_return_switch)

# Done with all the OS specific files we produce
# Now generate a few big files with all the typedefs
# and registration code. Note that we need to do this
# as a loop over each architecture, since we need to
# appropriately guard the code for each arch in an #ifdef
with open(os.path.join(DESTDIR, "gen_syscalls_ext_typedefs.h"), "w") as callbacktypes:
    print "Writing", "gen_syscalls_ext_typedefs.h"
    for GUARD in typedefs:
        callbacktypes.write(GUARD + "\n")
        for t in typedefs[GUARD]:
            callbacktypes.write(t+"\n")
        callbacktypes.write("#endif\n")

with open(os.path.join(DESTDIR, "gen_syscall_ppp_register_enter.cpp"), "w") as pppfile:
    print "Writing", "gen_syscall_ppp_register_enter.cpp"
    for GUARD in cb_names_enter:
        pppfile.write(GUARD + "\n")
        for ppp in cb_names_enter[GUARD]:
            pppfile.write("PPP_PROT_REG_CB({0})\n".format(ppp))
        pppfile.write("#endif\n")

with open(os.path.join(DESTDIR, "gen_syscall_ppp_register_return.cpp"), "w") as pppfile:
    print "Writing", "gen_syscall_ppp_register_return.cpp"
    for GUARD in cb_names_return:
        pppfile.write(GUARD + "\n")
        for ppp in cb_names_return[GUARD]:
            pppfile.write("PPP_PROT_REG_CB({0})\n".format(ppp))
        pppfile.write("#endif\n")


with open(os.path.join(DESTDIR, "gen_syscall_ppp_boilerplate_enter.cpp"), "w") as pppfile:
    print "Writing", "gen_syscall_ppp_boilerplate_enter.cpp"
    for GUARD in cb_names_enter:
        pppfile.write(GUARD + "\n")
        for ppp in cb_names_enter[GUARD]:
            pppfile.write("PPP_CB_BOILERPLATE({0})\n".format(ppp))
        pppfile.write("#endif\n")

with open(os.path.join(DESTDIR, "gen_syscall_ppp_boilerplate_return.cpp"), "w") as pppfile:
    print "Writing", "gen_syscall_ppp_boilerplate_return.cpp"
    for GUARD in cb_names_return:
        pppfile.write(GUARD + "\n")
        for ppp in cb_names_return[GUARD]:
            pppfile.write("PPP_CB_BOILERPLATE({0})\n".format(ppp))
        pppfile.write("#endif\n")

with open(os.path.join(DESTDIR, "gen_syscall_ppp_extern_enter.h"), "w") as pppfile:
    print "Writing", "gen_syscall_ppp_extern_enter.h"
    for GUARD in cb_names_enter:
        pppfile.write(GUARD + "\n")
        for ppp in cb_names_enter[GUARD]:
            pppfile.write("PPP_CB_EXTERN({0})\n".format(ppp))
        pppfile.write("#endif\n")

with open(os.path.join(DESTDIR, "gen_syscall_ppp_extern_return.h"), "w") as pppfile:
    print "Writing", "gen_syscall_ppp_extern_return.h"
    for GUARD in cb_names_return:
        pppfile.write(GUARD + "\n")
        for ppp in cb_names_return[GUARD]:
            pppfile.write("PPP_CB_EXTERN({0})\n".format(ppp))
        pppfile.write("#endif\n")

