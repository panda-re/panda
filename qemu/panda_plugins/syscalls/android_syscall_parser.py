
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

ARM_CALLNO = "env->regs[7]"
ARM_ARGS = ["env->regs[0]", "env->regs[1]", "env->regs[2]", "env->regs[3]", "env->regs[4]", "env->regs[5]", "env->regs[6]"]
ARM_SP = "env->regs[13]"
ARM_GUARD = "#ifdef TARGET_ARM"

X86_CALLNO = "EAX"
X86_ARGS = ["EBX", "ECX", "EDX", "ESI", "EDI", "EBP"]
X86_SP = "ESP"
# Linux's syscall ABI doesn't change between IA32 and AMD64
X86_GUARD = "TARGET_I386"

MODE = "ARM"

# set arch/OS specific args by mode
for x in ["CALLNO", "ARGS", "SP", "GUARD"]:
    locals()[x] = locals()["_".join([MODE, x])]

types_64 = ["loff_t", 'u64']
types_32 = ["int", "long", "size_t", 'u32', 'off_t', 'timer_t', '__s32', 'key_t', 
            'key_serial_t', 'mqd_t', 'clockid_t', 'aio_context_t', 'qid_t', 'old_sigset_t', 'union semun']
types_16 = ['old_uid_t', 'uid_t', 'mode_t', 'gid_t', 'pid_t']
types_pointer = ['cap_user_data_t', 'cap_user_header_t', '...']

alltext = ""
alltext += GUARD + "\n"

alltext += "switch( " + CALLNO + " ){\n"

alltext+= "// we use std::string so that we only do lookups into guest memory once and cache the result\n"

def copy_string(dest, source, fname):
    global alltext
    alltext+= "syscalls::string %s = log_string(%s, \"%s\");\n" % (dest, source,fname)

def record_address(dest, source, fname):
    global alltext
    alltext+= "target_ulong %s = log_pointer(%s, \"%s\");\n" %(dest, source, fname)
    
def record_32(dest, source, fname):
    global alltext
    alltext+= "uint32_t %s = log_32(%s, \"%s\");\n" %(dest, source, fname)

def record_64(dest, highsource, lowsource, fname):
    global alltext
    alltext+= "uint64_t %s = log_64(%s, %s, \"%s\");\n" %(dest, highsource, lowsource, fname)

CHAR_STAR = 'CHAR_STAR'
POINTER   = 'POINTER'
BYTES_8   = '8BYTE'
BYTES_4   = '4BYTE'
BYTES_2   = '2BYTE'
ARG_TYPE_TRANSLATIONS = { CHAR_STAR:  'syscalls::string', # pointer
                          POINTER:    'target_ulong', # pointer
                          BYTES_8:    'uint64_t',
                          BYTES_4:    'uint32_t',
                          BYTES_2:    'uint16_t',
                        }

CPP_RESERVED = {"new": "anew"}

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
        assert(newtype in ARG_TYPE_TRANSLATIONS.keys())
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

callback_defs = set()
# Goldfish kernel doesn't support OABI layer. Yay!
with open("android_arm_prototypes.txt") as armcalls:
    linere = re.compile("(\d+) (.+) (\w+)\((.*)\);")
    charre = re.compile("char.*\*")
    for line in armcalls:
        # Fields: <no> <return-type> <name><signature with spaces>
        fields = linere.match(line)
        callno = fields.group(1)
        rettype = fields.group(2)
        callname = fields.group(3)
        args = fields.group(4).split(',')
        arg_types = []
        alltext += "// " + str(callno)+" "+ str(rettype)+" "+ str(callname)+" "+ str(args) + '\n'
        for argno, arg in enumerate(args):
            # the .split() can leave us with args = ['']
            if arg == '':
                continue
            #alltext += callno, rettype, callname, args
            thisarg = Argument()
            if arg.endswith('*') or len(arg.split()) == 1:
                # no argname, just type
                argname = "arg{0}".format(argno)
            else:
                argname = arg.split()[-1]
            thisarg.name = argname
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
            elif arg.strip() == 'void':
                pass
            elif arg.strip() == 'unsigned' or (len(arg.split()) is 2 and arg.split()[0] == 'unsigned'):
                thisarg.type = BYTES_4
                arg_types.append(thisarg)
            else:
                alltext += "unknown:", arg
        alltext += "case " + callno + ": {\n"
        alltext += "record_syscall(\"%s\");\n" % callname
        argno = 0
        for i, val in enumerate(arg_types):
            arg_type = val.type
            arg_name = val.name
            if argno >= len(ARGS):
                alltext += "// out of registers. Use the stack!"+'\n'
                break
            if arg_type == CHAR_STAR:
                copy_string(arg_name, ARGS[argno], args[i])
            elif arg_type == POINTER:
                record_address(arg_name, ARGS[argno], args[i])
            elif arg_type == BYTES_4:
                record_32(arg_name, ARGS[argno], args[i])
            elif arg_type == BYTES_8:
                # alignment sadness. Linux tried to make sure none of these happen
                if (argno % 2) == 1:
                    alltext += "// skipping arg for alignment"+'\n'
                    argno+= 1
                    if argno >= len(ARGS):
                        alltext += "// out of registers. Use the stack!"+'\n'
                        break
                record_64(arg_name, ARGS[argno], ARGS[argno+1],args[i])
                argno+=1
            argno+=1
        # figure out callback definition
        callback_fn = "call_{0}_callback".format(callname)
        _args = ",".join(['env', 'pc'] + [x.name for i, x in enumerate(arg_types)])
        _args_types = ",".join(['CPUState* env', 'target_ulong pc'] + [ARG_TYPE_TRANSLATIONS[x.type] + " " + x.name for i, x in enumerate(arg_types)])
        callback_call = callback_fn+"(" +_args+");"
        callback_def  = callback_fn+"(" + _args_types+")"
        # call the callback
        alltext += callback_call+'\n'
        #remember to define a weak symbol for the callback later
        callback_defs.add(callback_def)
            
        alltext += "finish_syscall();"+'\n'
        alltext += "}; break;"+'\n'
    alltext += "default:"+'\n'
    alltext += "record_syscall(\"UNKNOWN\");"+'\n'
    alltext += "}"+'\n'
alltext+= "#endif\n"
weak_callbacks = ""
weak_callbacks += GUARD + "\n"
weak_callbacks+= """
#include "weak_callbacks.hpp"
extern "C"{
#include "cpu.h"
}

// weak-defined default empty callbacks for all syscalls
"""
for callback_def in callback_defs:
    weak_callbacks += "void __attribute__((weak)) {0} {{ }}\n".format(callback_def)
weak_callbacks+= """
#endif
"""
with open("weak_callbacks.cpp", "w") as weakfile:
    weakfile.write(weak_callbacks)

weak_callbacks = ""
weak_callbacks+= """
#include <string>

// This is *NOT* supposed to be required for C++ code.
// It's fixed in GCC-4.8 in C++11 mode.
#define __STDC_FORMAT_MACROS

#include "syscalls.hpp"

extern "C" {
#include "cpu.h"
}

// weak-defined default empty callbacks for all syscalls
"""
weak_callbacks += GUARD + "\n"
for callback_def in callback_defs:
    weak_callbacks += "void __attribute__((weak)) {0};\n".format(callback_def)
weak_callbacks+= """
#endif
"""
with open("weak_callbacks.hpp", "w") as weakfile:
    weakfile.write(weak_callbacks)

with open("syscall_printer.cpp", "w") as dispatchfile:
    dispatchfile.write(alltext)

