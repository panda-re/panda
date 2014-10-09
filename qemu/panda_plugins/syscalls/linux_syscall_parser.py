
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
from collections import defaultdict
from sys import argv

ARM_CALLNO = "env->regs[7]"
ARM_ARGS = ["env->regs[0]", "env->regs[1]", "env->regs[2]", "env->regs[3]", "env->regs[4]", "env->regs[5]", "env->regs[6]"]
ARM_SP = "env->regs[13]"
ARM_GUARD = "#ifdef TARGET_ARM"

X86_CALLNO = "EAX"
X86_ARGS = ["EBX", "ECX", "EDX", "ESI", "EDI", "EBP"]
X86_SP = "ESP"
# Linux's syscall ABI doesn't change between IA32 and AMD64
X86_GUARD = "#ifdef TARGET_I386"

PROTOS = "android_arm_prototypes.txt" if len(argv) < 2 else argv[1]
MODE = "ARM" if len(argv) < 3 else argv[2].upper()

# set arch/OS specific args by mode
for x in ["CALLNO", "ARGS", "SP", "GUARD"]:
    locals()[x] = locals()["_".join([MODE, x])]

twoword_types = ["unsigned int", "unsigned long"]

types_64 = ["loff_t", 'u64']
stypes_32 = ["int", "long", '__s32']
types_32 = ["unsigned int", "unsigned long", "size_t", 'u32', 'off_t', 'timer_t', 'key_t', 
            'key_serial_t', 'mqd_t', 'clockid_t', 'aio_context_t', 'qid_t', 'old_sigset_t', 'union semun']
types_16 = ['old_uid_t', 'uid_t', 'mode_t', 'gid_t', 'pid_t']
types_pointer = ['cap_user_data_t', 'cap_user_header_t', '__sighandler_t', '...']

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

def record_s32(dest, source, fname):
    global alltext
    alltext+= "int32_t %s = log_s32(%s, \"%s\");\n" %(dest, source, fname)

def record_64(dest, highsource, lowsource, fname):
    global alltext
    alltext+= "uint64_t %s = log_64(%s, %s, \"%s\");\n" %(dest, highsource, lowsource, fname)

CHAR_STAR = 'CHAR_STAR'
POINTER   = 'POINTER'
BYTES_8   = '8BYTE'
BYTES_4   = '4BYTE'
BYTES_2   = '2BYTE'
SIGNED_4  = '4SIGNED'
# C++ types for callback arguments
ARG_TYPE_TRANSLATIONS = { CHAR_STAR:  'syscalls::string', # pointer
                          POINTER:    'target_ulong', # pointer
                          BYTES_8:    'uint64_t',
                          BYTES_4:    'uint32_t',
                          SIGNED_4:   'int32_t',
                          BYTES_2:    'uint16_t',
                        }
# C types for callback arguments
ARG_TYPE_C_TRANSLATIONS = dict(ARG_TYPE_TRANSLATIONS)
ARG_TYPE_C_TRANSLATIONS[CHAR_STAR] = 'target_ulong'

# Functions to translate arguments to C++ callbacks to arguments to C callbacks
# Defaults to returning the C++ argument's name
CXX_ARG_TO_C_ARG = defaultdict(lambda: lambda x: x)
CXX_ARG_TO_C_ARG[CHAR_STAR] = lambda x: "{0}.get_vaddr()".format(x) # uses internals of syscalls::string

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


class Syscall(object):
    def __init__(self, name):
        self.cxxargs = None
        self.cxx_std_fn = None
        self.cargs = None
        self.args = None
        self.precall = None
        self.call_contents = None
        self.name = name

# Prototypes for internal C++ callbacks per syscall
callback_defs = set()
# Typedefs for PPP C callbacks
typedefs = set()
# Names of all PPP C callbacks
cb_names = set()
# map from callback_def to code that comes before it in cpp file
precall = {}
# map from callback_def to its content in cpp file
call_contents = {}
# map from callback_def to call name
call_names = {}

syscalls = [] # objects, having a set is useless for dedup

# Goldfish kernel doesn't support OABI layer. Yay!
with open(PROTOS) as armcalls:
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
                print arg
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
            elif arg_type == SIGNED_4:
                record_s32(arg_name, ARGS[argno], args[i])
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
        # each argument passed to C++ and C callbacks (the actual variable name or data)
        _args = ",".join(['env', 'pc'] + [x.name for i, x in enumerate(arg_types)])
        _c_args = ",".join(['env', 'pc'] + [CXX_ARG_TO_C_ARG[x.type](x.name) for i, x in enumerate(arg_types)])
        # declaration info (type and name) for each arg passed to C++ and C callbacks
        _args_types = ",".join(['CPUState* env', 'target_ulong pc'] + [ARG_TYPE_TRANSLATIONS[x.type] + " " + x.name for i, x in enumerate(arg_types)])
        _c_args_types = ",".join(['CPUState* env', 'target_ulong pc'] + [ARG_TYPE_C_TRANSLATIONS[x.type] + " " + x.name for i, x in enumerate(arg_types)])
        # call to the callback with C++ arguments
        callback_call = callback_fn+"(" +_args+");"
        # prototype for the C++ callback (with arg types and names)
        callback_def  = callback_fn+"(" + _args_types+")"
        # Check if this syscall has already be parsed
        # Android/Linux has two sigreturn calls
        if callback_def in call_names:
            # don't generate vectors and typedefs and callbacks for this syscall, we already have
            alltext += "PPP_RUN_CB(on_{0}, {1})\n".format(callname, _c_args)
            alltext += "finish_syscall();"+'\n'
            alltext += "}; break;"+'\n'
            continue # skip to next syscall
        call_names[callback_def] = callname
        
        # call the callback
        alltext += NAMESPACE + "::" + callback_call+'\n'
        #remember to define a weak symbol for the callback later
        callback_defs.add(callback_def)

        def gen_ret_callback_struct(callname, args):
            # now generate the struct to hold the arguments through the call
            calldataname = "{0}_calldata".format(callname)
            calldata = "struct {0} : public CallbackData {{\n".format(calldataname)
            calldata += "target_ulong pc;\n"
            for x in args:
                calldata += ARG_TYPE_TRANSLATIONS[x.type] + " " + x.name + ";\n"
            calldata += "};\n"
            return calldataname, calldata

        calldataname, calldata = gen_ret_callback_struct(callname, arg_types)

        def gen_ret_callback(callname, calldataname, args):
            # code to call the sysret callback using the struct contents
            sysretcallbackname = "{0}_returned".format(callname)
            sysretcallback = "static Callback_RC {0}(CallbackData* opaque, CPUState* env, target_asid asid)".format(sysretcallbackname)
            sysretcallback += "{\n"
            sysretcallback += "{0}* data = dynamic_cast<{0}*>(opaque);\n".format(calldataname)
            sysretcallback += 'if(!data) {fprintf(stderr,"oops\\n"); return Callback_RC::ERROR;}\n'
            _c_ret_args_list = ",".join(['env', 'data->pc'] + [ "data->" +CXX_ARG_TO_C_ARG[x.type](x.name) for i, x in enumerate(args)])
            sysretcallback += "PPP_RUN_CB(on_{0}, {1})\n".format(sysretcallbackname, _c_ret_args_list)
            sysretcallback += "return Callback_RC::NORMAL;\n"
            sysretcallback += "}\n"
            return sysretcallbackname, sysretcallback

        sysretcallbackname, sysretcallback = gen_ret_callback(callname, calldataname, arg_types)
        #define the syscall's c++ callback fn
        # C++ callback argument types, no names
        _args_only_types = ", ".join(['CPUState*', 'target_ulong'] + [ARG_TYPE_TRANSLATIONS[x.type] for x in arg_types])

        cxx_vector_name = "internal_registered_callback_" + callname
        cxx_std_fn = "std::function<void({0})>".format(_args_only_types)
        # Declare the callback list

        cxx_vector_type = "std::vector<" + cxx_std_fn+">"
        cxx_vector = cxx_vector_type +" " + cxx_vector_name
        # Build the register callback function
        cxx_register = "void {0}::register_call_{1}({2} callback){{\n".format(
                        NAMESPACE, callname, cxx_std_fn)
        cxx_register += cxx_vector_name +".push_back(callback);\n"
        cxx_register += "}\n"
        precall[callback_def] = cxx_vector + ";\n" + cxx_register+calldata+sysretcallback
        # code to populate the struct
        calldatafill  = "for (auto x: "+cxx_vector_name +"){\n"
        calldatafill += "    x({0});\n".format(_args)
        calldatafill += "}\n"
        calldatafill += "if (0 == ppp_on_{0}_num_cb) return;\n".format(sysretcallbackname)
        calldatafill += "{0}* data = new {0};\n".format(calldataname)
        calldatafill += "data->pc = pc;\n"
        for x in arg_types:
            calldatafill += "data->{0} = {0};\n".format(x.name)
        calldatafill += "appendReturnPoint(ReturnPoint(" +\
                        "calc_retaddr(env, pc),"+ \
                        " get_asid(env, pc),"+\
                        " data, {0}));".format(sysretcallbackname)
        call_contents[callback_def] = calldatafill

        cb_names.add("on_{0}".format(callname))
        cb_names.add("on_{0}".format(sysretcallbackname))
        # define a type for the callback
        typedef = "typedef void (*on_{0}_t)({1});".format(callname, _c_args_types)
        typedefs.add(typedef)
        typedefr= "typedef void (*on_{0}_t)({1});".format(sysretcallbackname, _c_args_types)
        typedefs.add(typedefr)
        alltext += "PPP_RUN_CB(on_{0}, {1})\n".format(callname, _c_args)

        alltext += "finish_syscall();"+'\n'
        alltext += "}; break;"+'\n'
        thiscall = Syscall(callname)
        thiscall.call_contents = calldatafill
        thiscall.precall = cxx_vector + ";\n" + cxx_register+calldata+sysretcallback
        thiscall.args = arg_types
        thiscall.cxx_std_fn = cxx_std_fn
        thiscall.callback_def = callback_def

        syscalls.append(thiscall)
        
    alltext += "default:"+'\n'
    alltext += "record_syscall(\"UNKNOWN\");"+'\n'
    alltext += "}"+'\n'
alltext+= "#endif\n"
weak_callbacks = ""
weak_callbacks+= """
#include "gen_callbacks.hpp"
extern "C"{
#include "cpu.h"
}

// weak-defined default empty callbacks for all syscalls
"""
weak_callbacks += GUARD + "\n"
for syscall in syscalls:
    weak_callbacks += syscall.precall
    weak_callbacks += "void {1}::{0} {{\n".format(syscall.callback_def, NAMESPACE)
    weak_callbacks += syscall.call_contents
    weak_callbacks += "}\n"
weak_callbacks+= """
#endif
"""
with open("gen_default_callbacks.cpp", "w") as weakfile:
    weakfile.write(weak_callbacks)

weak_callbacks = ""
weak_callbacks+= """#ifndef __gen_callbacks_hpp
#define __gen_callbacks_hpp
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
weak_callbacks += "namespace {0} {{\n".format(NAMESPACE)
for syscall in syscalls:
    weak_callbacks += "void register_call_{0}({1} callback);\n".format(syscall.name, syscall.cxx_std_fn);
    weak_callbacks += "void {0};\n".format(syscall.callback_def)
weak_callbacks+= """} //namespace syscalls
#endif
#endif //__gen_callbacks.hpp
"""
with open("gen_callbacks.hpp", "w") as weakfile:
    weakfile.write(weak_callbacks)

with open("gen_syscalls_ext_typedefs.h", "w") as callbacktypes:
    callbacktypes.write(GUARD + "\n")
    for t in typedefs:
        callbacktypes.write(t+"\n")
    callbacktypes.write("#endif\n")

with open("gen_syscall_printer.cpp", "w") as dispatchfile:
    dispatchfile.write(alltext)

with open("gen_syscall_ppp_register.cpp", "w") as pppfile:
    pppfile.write(GUARD + "\n")
    for ppp in cb_names:
        pppfile.write("PPP_PROT_REG_CB({0})\n".format(ppp))
    pppfile.write("#endif\n")

with open("gen_syscall_ppp_boilerplate.cpp", "w") as pppfile:
    pppfile.write(GUARD + "\n")
    for ppp in cb_names:
        pppfile.write("PPP_CB_BOILERPLATE({0})\n".format(ppp))
    pppfile.write("#endif\n")
