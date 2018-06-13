#!/usr/bin/env python2.7
# /* PANDABEGINCOMMENT
# *
# * Authors:
# *  Tim Leek                 tleek@ll.mit.edu
# *  Ryan Whelan              rwhelan@ll.mit.edu
# *  Joshua Hodosh            josh.hodosh@ll.mit.edu
# *  Michael Zhivich          mzhivich@ll.mit.edu
# *  Brendan Dolan-Gavitt     brendandg@gatech.edu
# *  Manolis Stamatogiannakis manolis.stamatogiannakis@vu.nl
# *
# * This work is licensed under the terms of the GNU GPL, version 2.
# * See the COPYING file in the top-level directory.
# *
#PANDAENDCOMMENT */

''' PANDA tool for generating different code files from system call definitions.
'''

from __future__ import print_function
import jinja2
import sys
import os
import re
import logging
import argparse



##############################################################################
### Definitions, not controlled through command line arguments ###############
##############################################################################

# Setup logging first thing in the morning.
LOGLEVEL = logging.INFO
logging.basicConfig(format='%(levelname)s: %(message)s', level=LOGLEVEL)

# Details about operating systems and architectures to be processed.
KNOWN_OS = ['linux', 'windows_7', 'windows_xpsp2', 'windows_xpsp3', 'windows_2000']
KNOWN_ARCH = {
    'x86': {
        'bits': 32,
        'rt_callno_reg': 'env->regs[R_EAX]',    # register holding syscall number at runtime
        'rt_sp_reg': 'env->regs[R_ESP]',        # register holding stack pointer at runtime
        'qemu_target': 'TARGET_I386',           # qemu target name for this arch - used in guards
    },
    'arm': {
        'bits': 32,
        'rt_callno_reg': 'env->regs[7]',        # register holding syscall number at runtime
        'rt_sp_reg': 'env->regs[13]',           # register holding stack pointer at runtime
        'qemu_target': 'TARGET_ARM',            # qemu target name for this arch - used in guards
    },
}

# This is the the maximum generic syscall number.
# We use this to tell apart special system calls (see last lines in arm prototypes).
MAX_GENERIC_SYSCALL = 1023

# Templates for per-arch typedefs and callback registration code files.
# Generated files will contain definitions for multiple architectures in guarded #ifdef blocks.
GENERATED_FILES = [
    ('syscalls_ext_typedefs.tpl', '.h'),
    ('syscall_ppp_register_enter.tpl', '.cpp'),
    ('syscall_ppp_register_return.tpl', '.cpp'),
    ('syscall_ppp_boilerplate_enter.tpl', '.cpp'),
    ('syscall_ppp_boilerplate_return.tpl', '.cpp'),
    ('syscall_ppp_extern_enter.tpl', '.h'),
    ('syscall_ppp_extern_return.tpl', '.h'),
]



##############################################################################
### Wrapper classes for system calls and arguments ###########################
##############################################################################
class ArgumentError(Exception):
    ''' Base error class for Argument related errors.
    '''
    pass

class EmptyArgumentError(ArgumentError):
    ''' Raised for empty or void arguments.
    '''
    pass

class Argument(object):
    ''' Wraps a system call argument.
    '''
    charre = re.compile("char.*\*")
    types = {
        'reserved': ['new', 'data', 'int', 'cpu'],
        'twoword': ['unsigned int', 'unsigned long'],
        'u64': ['loff_t', 'u64'],
        'u32': [
            'unsigned int', 'unsigned long', 'size_t', 'u32', 'off_t',
            'timer_t', 'key_t', 'key_serial_t', 'mqd_t', 'clockid_t',
            'aio_context_t', 'qid_t', 'old_sigset_t', 'union semun',
            'ULONG', 'SIZE_T', 'HANDLE', 'PBOOLEAN', 'PHANDLE',
            'PLARGE_INTEGER', 'PLONG', 'PSIZE_T', 'PUCHAR',
            'PULARGE_INTEGER', 'PULONG', 'PULONG_PTR',
            'PUNICODE_STRING', 'PVOID', 'PWSTR'
        ],
        's32': ['int', 'long', '__s32', 'LONG'],
        'u16': ['old_uid_t', 'uid_t', 'mode_t', 'gid_t', 'pid_t', 'USHORT'],
        'ptr': ['cap_user_data_t', 'cap_user_header_t', '__sighandler_t', '...'],
    }

    def __init__(self, arg, argno=-1, arch_bits=32):
        self.no = argno
        self.raw = arg.strip()
        self.arch_bits = arch_bits
        if self.raw == '' or self.raw == 'void':
            raise EmptyArgumentError()

        # parse argument name
        if self.raw.endswith('*') or len(self.raw.split()) == 1 or self.raw in Argument.types['twoword']:
            # no argname, just type
            self.name = "arg{0}".format(self.no)
        else:
            self.name = self.raw.split()[-1]

        # name sanitization
        self.name = self.name.lstrip('\t *')
        if self.name in Argument.types['reserved']:
            self.name = '_' + self.name
        elif self.name == ')':
            self.name = 'fn'
        self.name = self.name.rstrip('[]')

        # identify argument type
        if Argument.charre.search(self.raw) and not any([self.name.endswith('buf'), self.name == '...', self.name.endswith('[]')]):
            self.type = 'CHAR_STAR'
        elif any(['*' in self.raw, '[]' in self.raw, any([x in self.raw for x in Argument.types['ptr']])]):
            self.type = 'POINTER'
        elif any([x in self.raw for x in Argument.types['u64']]):
            self.type = '8BYTE'
        elif any([x in self.raw for x in Argument.types['u32']]) or any([x in self.raw for x in Argument.types['u16']]):
            self.type = '4BYTE'
        elif any([x in self.raw for x in Argument.types['s32']]) and 'unsigned' not in self.raw:
            self.type = '4SIGNED'
        elif self.raw == 'void':
            self.type = None
            assert False, 'Unexpected void argument.'
        elif self.raw == 'unsigned' or (len(self.raw.split()) == 2 and self.raw.split()[0] == 'unsigned'):
            self.type = '4BYTE'
        else:
            # Warn but assume it's a 32-bit argument
            logging.debug("%s not of known type, assuming 32-bit", self.raw)
            self.type = '4BYTE'

    @property
    def ctype(self):
        if self.type in ['CHAR_STAR', 'POINTER'] and self.arch_bits == 32:
            return 'uint32_t'
        elif self.type in ['CHAR_STAR', 'POINTER']:
            return 'uint64_t'
        elif self.type == '4BYTE':
            return 'uint32_t'
        elif self.type == '4SIGNED':
            return 'int32_t'
        elif self.type == '8BYTE':
            return 'uint64_t'
        elif self.type == '2BYTE':
            return 'uint16_t'
        assert False, 'Unknown type for argument %s: %s' % (self.name, self.type)

    @property
    def temp_decl_code(self):
        ''' Returns a snippet declaring an appropriate temp
            variable for this argument.
        '''
        return "{0} arg{1};".format(self.ctype, self.no)

    @property
    def temp_assg_code(self):
        ''' Returns a snippet declaring an appropriate temp
            variable for this argument and assigning its 
            runtime value to it.
        '''
        ctype = self.ctype
        ctype_bits = int(filter(str.isdigit, ctype))
        assert ctype_bits in [32, 64], 'Invalid number of bits for type %s' % ctype
        ctype_get = 'get_%d' % ctype_bits if ctype.startswith('uint') else 'get_s%d' % ctype_bits
        return "{0} arg{1} = {2}(cpu, {1});".format(ctype, self.no, ctype_get)

    @property
    def memcpy_temp2rp_code(self):
        ''' Returns a snippet that copies this argument from its
            corresponding temp into a return point structure.
        '''
        return 'memcpy(rp.params[{0}], &arg{0}, sizeof({1}));'.format(self.no, self.ctype)

    @property
    def memcpy_rp2temp_code(self):
        ''' Returns a snippet that copies this argument from 
            a return point structure into its corresponding temp.
        '''
        return 'memcpy(&arg{0}, rp.params[{0}], sizeof({1}));'.format(self.no, self.ctype)

class SysCallError(Exception):
    ''' Base error class for SysCall related errors.
    '''
    pass

class SysCallDefError(SysCallError):
    ''' Raised for prototype lines that can't be parsed.
    '''
    pass

class SysCall(object):
    ''' Wraps a system call.
    '''
    # Fields: <no> <return-type> <name><signature with spaces>
    linere = re.compile("(\d+) (.+) (\w+) ?\((.*)\);")

    def __init__(self, line, arch_bits=32):
        fields = SysCall.linere.match(line)
        if fields is None:
            raise SysCallDefError()

        self.no = int(fields.group(1))
        self.generic = False if self.no > MAX_GENERIC_SYSCALL else True
        self.rettype = fields.group(2)
        self.name = fields.group(3)
        self.args_raw = fields.group(4).split(',')
        self.arch_bits = arch_bits

        # process raw args
        self.args = []
        for arg in self.args_raw:
            try:
                self.args.append(Argument(arg, argno=len(self.args), arch_bits=self.arch_bits))
            except EmptyArgumentError:
                continue

    @property
    def cargs(self):
        ''' Returns the system call arguments.
            each argument passed to C++ and C callbacks (the actual variable name or data)
        '''
        return ', '.join(['cpu', 'pc'] + ['arg%d' % i for i in range(len(self.args))])

    @property
    def cargs_signature(self):
        ''' Returns the system call arguments.
            declaration info (type and name) for each arg passed to C++ and C callbacks
        '''
        return ', '.join(['CPUState* cpu', 'target_ulong pc'] + ['%s %s' % (x.ctype, x.name) for x in self.args])



##############################################################################
### Main #####################################################################
##############################################################################
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PANDA syscalls2 support files generator.')
    parser.add_argument('--target', '-t', action='append', required=True, help='Target os:arch tuple to process.')
    parser.add_argument('--prefix', '-p', default='gen', help='Generated files prefix.')
    parser.add_argument('--outdir', '-o', default='./f', help='Output directory.')
    parser.add_argument('--prototypes', default='./prototypes', help='Prototype directory.')
    parser.add_argument('--templates', default='./templates', help='Template directory.')
    parser.add_argument('--generate-info', default=False, action='store_true', help='Generate code for syscall info dynamic libraries.')
    args = parser.parse_args()

    assert os.path.isdir(args.outdir), 'Output directory %s does not exist.' % args.outdir
    assert os.path.isdir(args.templates), 'Template directory %s does not exist.' % args.templates
    logging.debug(args)

    # Create a Jinja2 environment for rendering templates.
    # Setting undefined to StrictUndefined will raise an error if a variable
    # used in rendering is missing from the template.
    j2env = jinja2.Environment(loader=jinja2.FileSystemLoader(args.templates),
            extensions=['jinja2.ext.loopcontrols',],
            undefined=jinja2.StrictUndefined)

    # Create a context dictionary, used for template rendering.
    # Notes:
    # Per-arch system call lists are used to generate typedefs
    # and names for PPP C callbacks. Having such a list allows
    # to only define once callbacks for system calls implemented
    # by multiple OSes.
    # XXX:
    # Add some check for system calls having the same name but
    # requiring different arguments.
    global_context = {
        'architectures': KNOWN_ARCH,
        'syscalls': {target: [] for target in args.target}, # per target system call list
        'syscalls_arch': {arch: {} for arch in KNOWN_ARCH}, # per arch system call list
    }

    # parse system call definitions for all targets
    for _target in args.target:
        _os, _arch = _target.split(':')
        assert (_os in KNOWN_OS and _arch in KNOWN_ARCH), 'Unknown os or arch. Please read help message.'
        logging.info('Processing system calls for %s', _target)

        protofile_name = os.path.join(args.prototypes, '%s_%s_prototypes.txt' % (_os, _arch))
        assert os.path.isfile(protofile_name), 'Missing prototype file %s' % protofile_name

        syscalls = global_context['syscalls'][_target]
        syscalls_arch = global_context['syscalls_arch'][_arch]
        target_context = {
            'arch': _arch,
            'os': _os,
            'syscalls': syscalls,
            'arch_conf': KNOWN_ARCH[_arch],
        }

        # Parse prototype file contents.
        # Notes:
        # Goldfish kernel doesn't support OABI layer. Yay!
        with open(protofile_name) as protofile:
            for lineno, line in enumerate(protofile, 1):
                try:
                    syscall = SysCall(line, arch_bits=KNOWN_ARCH[_arch]['bits'])
                    syscalls.append(syscall)
                    syscalls_arch[syscall.name] = syscall
                except SysCallDefError:
                    logging.debug('Bad prototype line in %s:%d: %s', protofile.name, lineno, line.rstrip())

        # Calculate the maximum number of arguments and system call number for this os/arch.
        target_context['max_syscall_args'] = max([len(s.args) for s in syscalls])
        target_context['max_syscall_no'] = max([s.no for s in syscalls])
        target_context['max_syscall_generic_no'] = max([s.no for s in syscalls if s.generic])

        # Render per-target output files.
        j2tpl = j2env.get_template('syscall_switch_enter.tpl')
        with open(os.path.join(args.outdir, "%s_syscall_switch_enter_%s_%s.cpp" % (args.prefix, _os, _arch)), "wb+") as of:
            logging.info("Writing %s", of.name)
            of.write(j2tpl.render(target_context))
        j2tpl = j2env.get_template('syscall_switch_return.tpl')
        with open(os.path.join(args.outdir, "%s_syscall_switch_return_%s_%s.cpp" % (args.prefix, _os, _arch)), "wb+") as of:
            logging.info("Writing %s", of.name)
            of.write(j2tpl.render(target_context))

        # Generate syscall info dynamic libraries.
        if args.generate_info:
            j2tpl = j2env.get_template('syscall_info.tpl')
            with open(os.path.join(args.outdir, "%s_syscall_info_%s_%s.c" % (args.prefix, _os, _arch)), "wb+") as of:
                logging.info("Writing %s", of.name)
                of.write(j2tpl.render(target_context))

    # Render big files.
    for tpl, ext in GENERATED_FILES:
        j2tpl = j2env.get_template(tpl)
        of_name = '%s_%s%s' % (args.prefix, os.path.splitext(os.path.basename(tpl))[0], ext)
        with open(os.path.join(args.outdir, of_name), 'wb+') as of:
            logging.info("Writing %s", of.name)
            of.write(j2tpl.render(global_context))

