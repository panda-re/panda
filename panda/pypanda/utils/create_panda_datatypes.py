#!/usr/bin/env python3
import re
import os
import sys
if sys.version_info[0] < 3:
    raise RuntimeError('Requires python3')

# Autogenerate panda_datatypes.py and include/panda_datatypes.h
#
# Both of these files contain info in or derived from stuff in
# panda/include/panda.  Here, we autogenerate the two files so that we
# never have to worry about how to keep them in sync with the info in
# those include files.  See panda/include/panda/README.pypanda for 
# so proscriptions wrt those headers we use here. They need to be kept
# fairly clean if we are to be able to make sense of them with this script
# which isn't terriby clever.
#

#XXX: When trying to install via pip these files get copied to /tmp and then our paths are all bad
OUTPUT_DIR = os.path.abspath(os.path.join(*[os.path.dirname(__file__), "..", "panda", "autogen"]))                       # panda-git/panda/pypanda/panda/autogen
PLUGINS_DIR = os.path.abspath(os.path.join(*[os.path.dirname(__file__), "..", "..", "plugins"]))                         # panda-git/panda/plugins
INCLUDE_DIR_PYP = os.path.abspath(os.path.join(*[os.path.dirname(__file__), "..", "..", "pypanda", "panda", "include"])) # panda-git/panda/pypanda/panda/include
INCLUDE_DIR_PAN = os.path.abspath(os.path.join(*[os.path.dirname(__file__), "..", "..", "include", "panda"]))            # panda-git/panda/include/panda



pypanda_start_pattern = """// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.
"""

pypanda_end_pattern = "// END_PYPANDA_NEEDS_THIS -- do not delete this comment!\n"


pypanda_headers = []

def is_panda_aware(filename):
    contents = open(filename).read()
    if pypanda_start_pattern in contents:
        if not pypanda_end_pattern in contents:
            raise RuntimeError(f"PANDA aware file {filename} missing pypanda end pattern")
        return True
    return False

def trim_pypanda(contents):
    '''
    Trim data between pypanda_start_pattern/pypanda_end_pattern
    return None if patterns aren't found
    '''
    a = contents.find(pypanda_start_pattern)
    if a == -1: return None
    a += len(pypanda_start_pattern)
    b = contents.find(pypanda_end_pattern)
    if b == -1: return None
    recurse = None
    if len(contents[b+len(pypanda_end_pattern):]):
        recurse = trim_pypanda(contents[b+len(pypanda_end_pattern):])
    if recurse:
        return contents[a:b]+recurse
    else:
        return contents[a:b]

def copy_syscalls_header(filename):
    # Different than regular because we don't auto add to
    # pypanda_headers and because we add PPP automatically - Should do for others somehow
    pypanda_h = os.path.join(INCLUDE_DIR_PYP, os.path.split(filename)[-1])
    print("Creating pypanda syscall header [%s] for [%s]" % (pypanda_h, filename))
    new_contents = []
    reg = re.compile(r"typedef void \(\*([a-zA-Z0-9_-]+)_t\).*")
    with open(filename, "r") as infile:
        for line in infile.readlines():
            new_contents.append(line.strip())
            # now add void ppp_add_cb_{cb_name}({cb_name}_t);
            m = reg.match(line)
            if m:
                name = m.groups(1)[0]
                new_contents.append(f"void ppp_add_cb_{name}({name}_t);")
                # void ppp_add_cb_{cb_name}(void (*)({cb_args}))
    with open(pypanda_h, "w") as outfile:
        outfile.write("\n".join(new_contents))


def create_pypanda_header(filename):
    '''
    Given a file name, copy it into pypanda's includes directory
    along with all nested includes it contians
    '''
    contents = open(filename).read()
    subcontents = trim_pypanda(contents)
    if not subcontents: return
    # look for local includes
    rest = []
    (plugin_dir,fn) = os.path.split(filename)
    for line in subcontents.split("\n"):
        foo = re.search('\#include "(.*)"$', line)
        if foo:
            nested_inc = foo.groups()[0]
            print("Found nested include of %s" % nested_inc)
            create_pypanda_header("%s/%s" % (plugin_dir,nested_inc))
        else:
            rest.append(line)
    new_contents = "\n".join(rest)
    foo = re.search("([^\/]+)\.h$", filename)
    assert (not (foo is None))
    pypanda_h = os.path.join(INCLUDE_DIR_PYP, foo.groups()[0])+".h"
    print("Creating pypanda header [%s] for [%s]" % (pypanda_h, filename))
    with open(pypanda_h, "w") as pyph:
        pyph.write(new_contents)
    pypanda_headers.append(pypanda_h)

def read_but_exclude_garbage(filename):
    nongarbage = []
    with open(filename) as thefile:
        for line in thefile:
            keep = True
            if re.search("^\s*\#", line): # Has preprocessor directive
                if not re.search("^\s*\#define [^_]", line): # Not a defines
                    keep = False
            if keep:
                nongarbage.append(line)
        return nongarbage

pn = None
def include_this(pdth, fn):
    global pn
    fn = os.path.join(INCLUDE_DIR_PAN, fn)
    shortpath= "/".join(fn.split("/")[-4:]) # Hardcoded 4, might be wrong
    pdth.write("\n\n// -----------------------------------\n")
    if is_panda_aware(fn):
        pdth.write("// Pull number %d from (panda-aware) %s\n" % (pn,shortpath))
        contents = open(fn).read()
        subcontents = trim_pypanda(contents)
        packed_re = re.compile(r'PACKED_STRUCT([a-zA-Z0-9_-]*)')
        if "PACKED_STRUCT" in subcontents: # Replace PACKED_STRUCT(foo) with foo. For kernelinfo.h
            for line in subcontents.split("\n"):
                if "PACKED_STRUCT" in line:
                    struct_name = re.search(r'PACKED_STRUCT\(([a-zA-Z0-9_-]*)\)', line).group(1)
                    line = line.replace(f"PACKED_STRUCT({struct_name})", f"struct {struct_name}")
                pdth.write(line+"\n")
        else:
                pdth.write(subcontents)
    else:
        pdth.write("// Pull number %d from %s\n" % (pn,shortpath))

        for line in read_but_exclude_garbage(fn):
            pdth.write(line)
    pn += 1


def main():
    global pn
    pn = 1
    # examine all plugin dirs looking for pypanda-aware headers and pull
    # out pypanda bits to go in INCLUDE_DIR files
    for plugin in os.listdir(PLUGINS_DIR):
        if plugin == ".git": continue
        plugin_dir = PLUGINS_DIR + "/" + plugin
        if os.path.isdir(plugin_dir):
            # just look for plugin_int_fns.h
            plugin_file = plugin + "_int_fns.h"
            if os.path.exists("%s/%s" % (plugin_dir, plugin_file)):
                print("Examining [%s] for pypanda-awareness" % plugin_file)
                create_pypanda_header("%s/%s" % (plugin_dir, plugin_file))

    # Also pull in a few special header files outside of plugin-to-plugin APIs. Note we already handled syscalls2 above
    for header in ["rr/rr_api.h", "plugin.h", "common.h"]:
        create_pypanda_header("%s/%s" % (INCLUDE_DIR_PAN, header))

    # Syscalls2: Handle autogenerated headers for all available archs
    syscalls_gen_dir = PLUGINS_DIR + "/syscalls2/generated"
    for header in os.listdir(syscalls_gen_dir):
        if header.startswith("syscalls_ext_typedefs_"):
            copy_syscalls_header("%s/%s" % (syscalls_gen_dir, header))

    with open(os.path.join(OUTPUT_DIR, "panda_datatypes.py"), "w") as pdty:
        pdty.write("""
# NOTE: panda_datatypes.py is auto generated by the script create_panda_datatypes.py
# Please do not tinker with it!  Instead, fix the script that generates it
from enum import Enum
from ctypes import *
from collections import namedtuple
from ..ffi_importer import ffi

def read_cleanup_header(fname):
    # CFFI can't handle externs, but sometimes we have to extern C (as opposed to 
    r = open(fname).read()
    for line in r.split("\\n"):
        assert("extern \\"C\\" {{" not in line), "Externs unsupported by CFFI. Change {{}} to a single line without braces".format(r)
    r = r.replace("extern \\"C\\" ", "") # This allows inline externs like 'extern "C" void foo(...)'
    return r

from os import environ

bits = int(environ["PANDA_BITS"])
arch = environ["PANDA_ARCH"]

ffi.cdef("typedef uint"+str(bits)+"_t target_ulong;")
#ffi.cdef(read_cleanup_header("{inc}/pthreadtypes.h"))

if arch == "i386":
	ffi.cdef(read_cleanup_header("{inc}/panda_datatypes_X86_32.h"))
	ffi.cdef(read_cleanup_header("{inc}/syscalls_ext_typedefs_x86.h"))
elif arch == "x86_64":
	ffi.cdef(read_cleanup_header("{inc}/panda_datatypes_X86_64.h"))
	ffi.cdef(read_cleanup_header("{inc}/syscalls_ext_typedefs_x64.h"))
elif arch == "arm":
	ffi.cdef(read_cleanup_header("{inc}/panda_datatypes_ARM_32.h"))
	ffi.cdef(read_cleanup_header("{inc}/syscalls_ext_typedefs_arm.h"))
elif arch == "ppc" and int(bits) == 32:
    ffi.cdef(read_cleanup_header("{inc}/panda_datatypes_PPC_32.h"))
    print('WARNING: no syscalls support for PPC 32')
elif arch == "ppc" and int(bits) == 64:
    ffi.cdef(read_cleanup_header("{inc}/panda_datatypes_PPC_64.h"))
    print('WARNING: no syscalls support for PPC 64')
else:
	print("PANDA_DATATYPES: Architecture not supported")

#ffi.cdef(read_cleanup_header("{inc}/panda_qemu_support.h"))
ffi.cdef(read_cleanup_header("{inc}/panda_datatypes.h"))
ffi.cdef(read_cleanup_header("{inc}/panda_osi.h"))
""".format(inc=INCLUDE_DIR_PYP))

        for pypanda_header in pypanda_headers:
            pdty.write('ffi.cdef(read_cleanup_header("%s"))\n' % pypanda_header)

        pdty.write("""
# so we need access to some data structures, but don't actually
# want to open all of libpanda yet because we don't have all the
# file information. So we just open libc to access this.
C = ffi.dlopen(None)

class PandaState(Enum):
    UNINT = 1
    INIT_DONE = 2
    IN_RECORD = 3
    IN_REPLAY = 4
    """)

        cbn = 0
        cb_list = {}
        with open (os.path.join(INCLUDE_DIR_PAN, "callbacks/cb-defs.h")) as fp:
            for line in fp:
                foo = re.search("^(\s+)PANDA_CB_([^,]+)\,", line)
                if foo:
                    cbname = foo.groups()[1]
                    cbname_l = cbname.lower()
                    cb_list[cbn] = cbname_l
                    cbn += 1
        cb_list[cbn] = "last"
        cbn += 1

        pdty.write('\nPandaCB = namedtuple("PandaCB", "init \\\n')
        for i in range(cbn-1):
            pdty.write(cb_list[i] + " ")
            if i == cbn-2:
                pdty.write('")\n')
            else:
                pdty.write("\\\n")

        in_tdu = False
        cb_types = {}
        with open (os.path.join(INCLUDE_DIR_PAN, "callbacks/cb-defs.h")) as fp:
            for line in fp:
                foo = re.search("typedef union panda_cb {", line)
                if foo:
                    in_tdu = True
                    continue
                foo = re.search("} panda_cb;", line)
                if foo:
                    in_tdu = False
                    continue
                if in_tdu:
                    # int (*before_block_translate)(CPUState *env, target_ulong pc);
                    for i in range(cbn):
                        foo = re.search("^\s+(.*)\s+\(\*%s\)\((.*)\);" % cb_list[i], line)
                        if foo:
                            rvtype = foo.groups()[0]
                            params = foo.groups()[1]
                            partypes = []
                            for param in params.split(','):
                                j = 1
                                while True:
                                    c = param[-j]
                                    if not (c.isalpha() or c.isnumeric() or c=='_'):
                                        break
                                    if j == len(param):
                                        break
                                    j += 1
                                if j == len(param):
                                    typ = param
                                else:
                                    typ = param[:(-j)+1].strip()
                                partypes.append(typ)
                            cb_typ = rvtype + " (" +  (", ".join(partypes)) + ")"
                            cb_name = cb_list[i]
                            cb_types[i] = (cb_name, cb_typ)

        # Sanity check: each callback must exist in both panda_cb_type and function definition
        for i in range(cbn-1):
            if i not in cb_types:
                raise RuntimeError(f"Error parsing code for '{cb_list[i]}' in callbacks/cb-defs.h. Is it defined both in panda_cb_type enum and as a prototype later with the same name?")

        pdty.write("""
pcb = PandaCB(init = ffi.callback("bool(void*)"),
""")

        for i in range(cbn-1):
            pdty.write('%s = ffi.callback("%s")' % cb_types[i])
            if i == cbn-2:
                pdty.write(")\n")
            else:
                pdty.write(",\n")

        pdty.write("""

pandacbtype = namedtuple("pandacbtype", "name number")

""")

        pdty.write("""
callback_dictionary = {
pcb.init : pandacbtype("init", -1),
""")


        for i in range(cbn-1):
            cb_name = cb_list[i]
            cb_name_up = cb_name.upper()
            pdty.write('pcb.%s : pandacbtype("%s", C.PANDA_CB_%s)' % (cb_name, cb_name, cb_name_up))
            if i == cbn-2:
                pdty.write("}\n")
            else:
                pdty.write(",\n")



    #########################################################
    #########################################################
    # second, create panda_datatypes.h by glomming together
    # files in panda/include/panda

    with open(os.path.join(INCLUDE_DIR_PYP, "panda_datatypes.h"), "w") as pdth:

        pdth.write("""
// NOTE: panda_datatypes.h is auto generated by the script create_panda_datatypes.py
// Please do not tinker with it!  Instead, fix the script that generates it

#define PYPANDA 1

""")
        # probably a better way... 
        pdth.write("typedef target_ulong target_ptr_t;\n")

        # XXX: These are defined in plugin.h, but we can't include all of plugin.h
        #      here without redefining things. Necessary for something? cb-defs?
        pdth.write("#define MAX_PANDA_PLUGINS 16\n")
        pdth.write("#define MAX_PANDA_PLUGIN_ARGS 32\n")

        for filename in ["callbacks/cb-defs.h",
                        f"{PLUGINS_DIR}/osi_linux/utils/kernelinfo/kernelinfo.h",
                         "panda_api.h", ]:
            include_this(pdth, filename)

if __name__ == '__main__':
    main()
