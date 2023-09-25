#!/usr/bin/env python3
# /* PANDABEGINCOMMENT
# *
# * Authors:
# *  Tim Leek                 tleek@ll.mit.edu
# *  Ryan Whelan              rwhelan@ll.mit.edu
# *  Joshua Hodosh            josh.hodosh@ll.mit.edu
# *  Michael Zhivich          mzhivich@ll.mit.edu
# *  Brendan Dolan-Gavitt     brendandg@gatech.edu
# *  Manolis Stamatogiannakis manolis.stamatogiannakis@vu.nl
# *  Luke Craig               luke.craig@ll.mit.edu
# *
# * This work is licensed under the terms of the GNU GPL, version 2.
# * See the COPYING file in the top-level directory.
# *
#PANDAENDCOMMENT */

''' PANDA tool for generating different code files from system call definitions.
'''


import jinja2
import json
import os
import contextlib
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
KNOWN_OS = ['linux', 'windows_7', 'windows_xpsp2', 'windows_xpsp3', 'windows_2000', 'freebsd']
KNOWN_ARCH = {
    'x64': {
        'bits': 64,
        'rt_callno_reg': 'env->regs[R_EAX]',    # register holding syscall number at runtime
        'rt_sp_reg': 'env->regs[R_ESP]',        # register holding stack pointer at runtime
        'qemu_target': 'defined(TARGET_X86_64)',  # qemu target name for this arch - used in guards
    },
    'x86': {
        'bits': 32,
        'rt_callno_reg': 'env->regs[R_EAX]',    # register holding syscall number at runtime
        'rt_sp_reg': 'env->regs[R_ESP]',        # register holding stack pointer at runtime
        'qemu_target': 'defined(TARGET_I386) && !defined(TARGET_X86_64)',  # qemu target name for this arch - used in guards
    },
    'arm': {
        'bits': 32,
        'rt_callno_reg': 'env->regs[7]',        # register holding syscall number at runtime
        'rt_sp_reg': 'env->regs[13]',           # register holding stack pointer at runtime
        'qemu_target': 'defined(TARGET_ARM) && !defined(TARGET_AARCH64)',   # qemu target name for this arch - used in guards
    },
    'arm64': {
        'bits': 64,
        'rt_callno_reg': 'env->xregs[8]',        # register holding syscall number at runtime (env->pc)
        'rt_sp_reg': 'env->regs[31]',           # register holding stack pointer at runtime (env->sp)
        'qemu_target': 'defined(TARGET_ARM) && defined(TARGET_AARCH64)',   # qemu target name for this arch - used in guards
    },
    'mips': {
        'bits': 32,
        'rt_callno_reg': 'env->active_tc.gpr[2]', # register holding syscall number at runtime ($v0)
        'rt_sp_reg': 'env->active_tc.gpr[29]',    # register holding stack pointer at runtime ($sp)
        'qemu_target': 'defined(TARGET_MIPS) && !defined(TARGET_MIPS64)',    # qemu target name for this arch - used in guards
        'runner_target': 'defined(TARGET_MIPS)',    # alternative target if another arch could be used
    },
    'mips64n32': {
        'bits': 32,
        'rt_callno_reg': 'env->active_tc.gpr[2]', # register holding syscall number at runtime ($v0)
        'rt_sp_reg': 'env->active_tc.gpr[29]',    # register holding stack pointer at runtime ($sp)
        'qemu_target': 'defined(TARGET_MIPS) && !defined(TARGET_MIPS64)',    # qemu target name for this arch - used in guards
        'runner_target': 'defined(TARGET_MIPS) && defined(TARGET_MIPS64)',    # alternative target if another arch could be used
        'boilerplate_target': '0',
    },
    'mips64': {
        'bits': 64,
        'rt_callno_reg': 'env->active_tc.gpr[2]', # register holding syscall number at runtime ($v0)
        'rt_sp_reg': 'env->active_tc.gpr[29]',    # register holding stack pointer at runtime ($sp)
        'qemu_target': 'defined(TARGET_MIPS) && defined(TARGET_MIPS64)',    # qemu target name for this arch - used in guards
    }
}

# This is the the maximum generic syscall number.
# We use this to tell apart arch-specific system calls (see last lines in arm prototypes).
MAX_GENERIC_SYSCALL = 1023
MAX_GENERIC_SYSCALL_ALT = 6000 # Compensate for MIPS ABI offsets

# Templates for per-arch typedefs and callback registration code files.
# Generated files will contain definitions for multiple architectures in guarded #ifdef blocks.
GENERATED_FILES = [
    ('syscalls_ext_typedefs.tpl', '.h'),
    ('syscalls_numbers.tpl', '.h'),
    ('syscalls_args.tpl', '.h'),
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

    # the "reserved" list consists of system call argument names that also
    # happen to be reserved words; "cpu" is reserved because the generated
    # callbacks for system calls also have a "CPUState *cpu" argument
    # the "twoword" list consists of two-word argument types in the system
    # calls which are used in a context without argument names
    # the "ptr" list is types used in system calls which ARE pointers
    # the other lists are just the types for the associated arch_bits which are
    # of the size & signedness associated with the list name
    # the default type is U32, so any type that should map to something else
    # needs to be listed explicitly
    # list for arch_bits=32
    types32 = {
        'reserved': ['new', 'data', 'int', 'cpu'],
        'twoword': ['unsigned int', 'unsigned long'],
        'u64': ['loff_t', 'u64'],
        's64': [],
        'u32': [
            'unsigned int', 'unsigned long', 'size_t', 'u32', 'off_t',
            'timer_t', 'key_t', 'key_serial_t', 'mqd_t', 'clockid_t',
            'aio_context_t', 'qid_t', 'old_sigset_t', 'union semun',
            'ULONG', 'SIZE_T', 'HANDLE', 'PBOOLEAN', 'PHANDLE',
            'PLARGE_INTEGER', 'PLONG', 'PSIZE_T', 'PUCHAR',
            'PULARGE_INTEGER', 'PULONG', 'PULONG_PTR',
            'PUNICODE_STRING', 'PVOID', 'PWSTR'
        ],
        's32': ['int', 'long', '__s32', 'pid_t', 'LONG'],
        'u16': ['old_uid_t', 'uid_t', 'mode_t', 'gid_t', 'USHORT'],
        'ptr': ['cap_user_data_t', 'cap_user_header_t', '__sighandler_t', '...'],
    }
    # list for arch_bits=64
    types64 = {
        'reserved': ['new', 'data', 'int', 'cpu'],
        'twoword': ['unsigned int', 'unsigned long'],
        'u64': [
            'loff_t', 'u64', 'unsigned long', 'off_t', 'aio_context_t',
            'ALPC_HANDLE', 'HANDLE', 'KAFFINITY', 'LPGUID', 'PACCESS_MASK',
            'PALPC_CONTEXT_ATTR', 'PALPC_DATA_VIEW_ATTR', 'PALPC_HANDLE',
            'PALPC_MESSAGE_ATTRIBUTES', 'PALPC_PORT_ATTRIBUTES',
            'PALPC_SECURITY_ATTR', 'PBOOLEAN', 'PBOOT_ENTRY', 'PBOOT_OPTIONS',
            'PCHAR', 'PCLIENT_ID', 'PCONTEXT', 'PCRM_PROTOCOL_ID',
            'PDBGUI_WAIT_STATE_CHANGE', 'PEFI_DRIVER_ENTRY', 'PEXECUTION_STATE',
            'PEXCEPTION_RECORD', 'PFILE_BASIC_INFORMATION',
            'PFILE_IO_COMPLETION_INFORMATION', 'PFILE_NETWORK_OPEN_INFORMATION',
            'PFILE_PATH', 'PFILE_SEGMENT_ELEMENT', 'PGENERIC_MAPPING',
            'PGROUP_AFFINITY', 'PHANDLE', 'PINITIAL_TEB', 'PIO_APC_ROUTINE',
            'PIO_STATUS_BLOCK', 'PJOB_SET_ARRAY', 'PKEY_VALUE_ENTRY',
            'PKTMOBJECT_CURSOR', 'PLARGE_INTEGER', 'PLCID', 'PLONG', 'PLUID',
            'PULONG', 'PNTSTATUS', 'POBJECT_ATTRIBUTES', 'POBJECT_TYPE_LIST',
            'PPLUGPLAY_EVENT_BLOCK', 'PPORT_MESSAGE', 'PPORT_VIEW',
            'PPRIVILEGE_SET', 'PPROCESS_ATTRIBUTE_LIST', 'PPROCESS_CREATE_INFO',
            'PPS_APC_ROUTINE', 'PPS_ATTRIBUTE_LIST', 'PREMOTE_PORT_VIEW',
            'PRTL_ATOM', 'PRTL_USER_PROCESS_PARAMETERS', 'PSECURITY_DESCRIPTOR',
            'PSECURITY_QUALITY_OF_SERVICE', 'PSID', 'PSIZE_T',
            'PTIMER_APC_ROUTINE', 'PTOKEN_DEFAULT_DACL', 'PTOKEN_GROUPS',
            'PTOKEN_OWNER', 'PTOKEN_PRIMARY_GROUP', 'PTOKEN_PRIVILEGES',
            'PTOKEN_SOURCE', 'PTOKEN_USER', 'PTRANSACTION_NOTIFICATION',
            'PULARGE_INTEGER', 'PULONG', 'PULONG_PTR', 'PUNICODE_STRING',
            'PUSHORT', 'PVOID', 'PWSTR', 'SIZE_T', 'ULONG_PTR'
            ],
        's64': ['long'],
        'u32': [
            'unsigned int', 'size_t', 'u32', 'rwf_t',
            'timer_t', 'key_t', 'key_serial_t', 'mqd_t', 'clockid_t',
            'qid_t', 'old_sigset_t', 'union semun', 'ULONG'
        ],
        's32': ['int', '__s32', 'pid_t', 'LONG'],
        'u16': ['old_uid_t', 'uid_t', 'mode_t', 'gid_t', 'USHORT'],
        'ptr': ['cap_user_data_t', 'cap_user_header_t', '__sighandler_t', '...'],
    }

    def __init__(self, arg, argno=-1, arch_bits=32):
        self.no = argno
        self.raw = arg.strip()
        self.arch_bits = arch_bits
        if self.raw == '' or self.raw == 'void':
            raise EmptyArgumentError()
        self.struct_name = "n/a"

        typesforbits = Argument.types32
        if (64 == arch_bits):
            typesforbits = Argument.types64

        # parse argument name
        if self.raw.endswith('*') or len(self.raw.split()) == 1 or self.raw in typesforbits['twoword']:
            # no argname, just type
            self.name = "arg{0}".format(self.no)
        else:
            self.name = self.raw.split()[-1]

        # name sanitization
        self.name = self.name.lstrip('\t *')
        if self.name in typesforbits['reserved']:
            self.name = '_' + self.name
        elif self.name == ')':
            self.name = 'fn'
        self.name = self.name.rstrip('[]')

        # identify argument type
        # types defined above are matched against the whole raw argument string
        # this means that e.g. mode_t will also match a umode_t argument
        if Argument.charre.search(self.raw) and not any([self.name.endswith('buf'), self.name == '...', self.name.endswith('[]')]):
            self.type = 'STR_PTR'
        elif any(['*' in self.raw, '[]' in self.raw, any([x in self.raw for x in typesforbits['ptr']])]) and (not 'struct' in self.raw) and (not '_t' in self.raw):
            self.type = 'BUF_PTR'
        elif any(['*' in self.raw, '[]' in self.raw, any([x in self.raw for x in typesforbits['ptr']])]) and any(['struct' in self.raw, '_t' in self.raw]):
            self.type = 'STRUCT_PTR'
            words = self.raw.split(" ")
            try:
                struct_idx = words.index("struct")
                self.struct_name = words[struct_idx + 1]
            except:
                self.struct_name = next(filter(lambda w: w.endswith("_t"), words), self.struct_name)

        # TODO: how to map to C type?
        #elif ('struct' in self.raw):
        #    self.type = 'STRUCT'
        elif any([x in self.raw for x in typesforbits['u64']]):
            self.type = 'U64'
        elif any([x in self.raw for x in typesforbits['s64']]):
            self.type = 'S64'
        elif any([x in self.raw for x in typesforbits['u32']]):
            self.type = 'U32'
        elif any([x in self.raw for x in typesforbits['u16']]):
            self.type = 'U32'   # is this correct?
        elif any([x in self.raw for x in typesforbits['s32']]) and 'unsigned' not in self.raw:
            self.type = 'S32'
        elif self.raw == 'void':
            self.type = None
            assert False, 'Unexpected void argument.'
        elif self.raw == 'unsigned' or (len(self.raw.split()) == 2 and self.raw.split()[0] == 'unsigned'):
            self.type = 'U32'
        else:
            # Warn but assume it's a 32-bit argument
            logging.debug("%s not of known type, assuming 32-bit", self.raw)
            self.type = 'U32'
        #print('\t', self.type)

    def __repr__(self):
        return '{0} {1}'.format(self.ctype, self.name)

    @property
    def ctype(self):
        if self.type in ['STR_PTR', 'BUF_PTR', 'STRUCT_PTR'] and self.arch_bits == 32:
            return 'uint32_t'
        elif self.type in ['STR_PTR', 'BUF_PTR', 'STRUCT_PTR']:
            return 'uint64_t'
        elif self.type == 'U32':
            return 'uint32_t'
        elif self.type == 'S32':
            return 'int32_t'
        elif self.type == 'U64':
            return 'uint64_t'
        elif self.type == 'S64':
            return 'int64_t'
        elif self.type == 'U16':
            return 'uint16_t'
        assert False, f'Unknown type for argument {self.name}: {self.type}'

    def emit_local_declaration(self, ctxp, prefix, unused=True):
        ''' Returns a snippet declaring a local variable for this
            argument and assigning it from context pointer ctxp.
        '''
        if unused:
            decl = '{2} UNUSED({0}{1})'.format(prefix, self.name, self.ctype)
        else:
            decl = '{2} {0}{1}'.format(prefix, self.name, self.ctype)
        return '{1} = *({2} *)(({0})->args[{3}]);'.format(
                ctxp, decl, self.ctype, self.no)

    def emit_reference_declaration(self, ctxp, prefix, unused=True, const=False):
        ''' Returns a snippet declaring a reference for this
            argument and assigning it from context pointer ctxp.
        '''
        if unused:
            decl = '{3}{2} &UNUSED({0}{1})'.format(
                    prefix, self.name, self.ctype, 'const ' if const else '')
        else:
            decl = '{3}{2} &{0}{1}'.format(
                    prefix, self.name, self.ctype, 'const ' if const else '')
        return '{1} = *reinterpret_cast<{4}{2} *>(({0})->args[{3}]);'.format(
                ctxp, decl, self.ctype, self.no, 'const ' if const else '')

    def emit_temp_declaration(self):
        ''' Returns a snippet declaring an appropriate temp
            variable for this argument.
        '''
        return '{0} arg{1} = 0;'.format(self.ctype, self.no)

    # no longer in use. see syscall.temp_assignments()
    # def emit_temp_assignment(self):
    #     ''' Returns a snippet declaring an appropriate temp
    #         variable for this argument and assigning its
    #         runtime value to it.
    #     '''
    #     ctype = self.ctype
    #     ctype_bits = int(''.join(filter(str.isdigit, ctype)))
    #     assert ctype_bits in [32, 64], 'Invalid number of bits for type %s' % ctype
    #     ctype_get = 'get_%d' % ctype_bits if ctype.startswith('uint') else 'get_s%d' % ctype_bits
    #     return '{0} arg{1} = {2}(cpu, {1});'.format(ctype, self.no, ctype_get)

    def emit_memcpy_temp_to_ref(self):
        ''' Returns a snippet that copies this argument from its
            corresponding temp into a syscall context structure.
            The syscall context is assumed to be a pointer.
        '''
        return 'memcpy(ctx.args[{0}], &arg{0}, sizeof({1}));'.format(self.no, self.ctype)

    def emit_memcpy_ref_to_temp(self):
        ''' Returns a snippet that copies this argument from
            a syscall context structure into its corresponding temp.
            The syscall context is assumed to be a pointer.
        '''
        return 'memcpy(&arg{0}, ctx.args[{0}], sizeof({1}));'.format(self.no, self.ctype)

    def emit_memcpy_temp_to_ptr(self):
        ''' Returns a snippet that copies this argument from its
            corresponding temp into a syscall context structure.
            The syscall context is assumed to be a pointer.
        '''
        return 'memcpy(&ctx->args[{0}], &arg{0}, sizeof({1}));'.format(self.no, self.ctype)

    def emit_memcpy_ptr_to_temp(self):
        ''' Returns a snippet that copies this argument from
            a syscall context structure into its corresponding temp.
            The syscall context is assumed to be a pointer.
        '''
        return 'memcpy(&arg{0}, ctx->args[{0}], sizeof({1}));'.format(self.no, self.ctype)

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

    def __init__(self, fields, target_context={}):
        max_generic_syscall = MAX_GENERIC_SYSCALL_ALT if target_context['arch'] in ['mips', 'mips64n32', 'mips64'] else MAX_GENERIC_SYSCALL

        # set properties inferred from prototype
        self.nos = [int(fields.group(1))] # "nos' is a list of syscall numbers, often 1 element
        self.generic = max(self.nos) <= max_generic_syscall
        self.rettype = fields.group(2)
        self.name = fields.group(3)
        self.args_raw = [[arg.strip() for arg in fields.group(4).split(',')]]
        self.target_context = target_context

        # set properties inferred from target context
        self.arch_bits = target_context['arch_conf']['bits']
        panda_noreturn_names = target_context.get('panda_noreturn', {})
        self.panda_noreturn = self.name in panda_noreturn_names
        panda_doublereturn_names = target_context.get('panda_doublereturn', {})
        self.panda_double_return = self.name in panda_doublereturn_names

        # process raw args at construction
        self.args = []
        for arg in self.args_raw[0]:
            try:
                self.args.append(Argument(arg, argno=len(self.args), arch_bits=self.arch_bits))
            except EmptyArgumentError:
                continue
        #print(self)

    def __repr__(self):
        return '{0}{1}'.format(self.name, self.args)

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
        return ', '.join(
            ['CPUState* cpu', 'target_ulong pc']
            + [f'{x.ctype} {x.name}' for x in self.args]
        )
    
    def temp_assignments(self):
        values = []
        argnum, argpos = 0, 0
        while argnum < len(self.args):
            ctype = self.args[argnum].ctype
            ctype_bits = int(''.join(filter(str.isdigit, ctype)))
            assert ctype_bits in {32, 64}, f'Invalid number of bits for type {ctype}'
            ctype_get = 'get_%d' % ctype_bits if ctype.startswith('uint') else 'get_s%d' % ctype_bits
            if self.arch_bits == 32 and ctype in ['uint64_t', 'int64_t']:
                if self.target_context['arch'] == 'arm' and argpos % 2 != 0:
                    # in this case, a zero is placed in this register in 
                    # in order to make 64-bit arguments aligned on even 
                    # registers
                    argpos += 1
                values.append(
                        f'{ctype} arg{argnum} = ({ctype})get_32(cpu, &ctx, {argpos+1}) << 32 | ({ctype})get_32(cpu, &ctx, {argpos});'
                )
                argpos += 2
            else:
                values.append(f'{ctype} arg{argnum} = {ctype_get}(cpu, &ctx, {argpos});')
                argpos += 1
            argnum += 1

        return '\n\t\t'.join(values)


##############################################################################
### Main #####################################################################
##############################################################################
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PANDA syscalls2 support source files generator.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--target', '-t', action='append', required=True, help='Target os:arch tuple to process.')
    parser.add_argument('--prefix', '-p', default='', help='Generated files prefix.')
    parser.add_argument('--outdir', '-o', default='../generated', help='Output directory.')
    parser.add_argument('--prototypes', default='../generated-in', help='Prototypes directory.')
    parser.add_argument('--templates', default='../generated-tpl', help='Template directory.')
    parser.add_argument('--context-target', default=None, help='JSON file with per-target context to be used for rendering output.')
    parser.add_argument('--generate-info', default=False, action='store_true', help='Generate code for syscall info dynamic libraries.')
    args = parser.parse_args()
    logging.debug(args)

    # Sanity checks.
    assert os.path.isdir(
        args.outdir
    ), f'Output directory {args.outdir} does not exist.'
    assert os.path.isdir(
        args.prototypes
    ), f'Output directory {args.prototypes} does not exist.'
    assert os.path.isdir(
        args.templates
    ), f'Template directory {args.templates} does not exist.'

    # Fields: <no> <return-type> <name><signature with spaces>
    prototype_linere = re.compile("(\d+) (.+) (\w+) ?\((.*)\);")

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
        'global_max_syscall_args': 0,
        'global_max_syscall_no': 0,
        'global_max_syscall_generic_no': 0,
    }

    # load extra target context
    if args.context_target is not None:
        with open(args.context_target) as args.context_target_file:
            context_target_extra = json.load(args.context_target_file)
    else:
        context_target_extra = {}
    
    arch_scs = {arch: {} for arch in KNOWN_ARCH}

    # delete old typedefs when we run this
    for _target in args.target:
        _os, _arch = _target.split(':')
        assert (_os in KNOWN_OS and _arch in KNOWN_ARCH), 'Unknown os or arch. Please read help message.'

        with contextlib.suppress(FileNotFoundError):
            os.remove(f'{args.prefix}syscalls_ext_typedefs_*.h')

    

    # parse system call definitions for all targets
    for _target in args.target:
        _os, _arch = _target.split(':')
        assert (_os in KNOWN_OS and _arch in KNOWN_ARCH), 'Unknown os or arch. Please read help message.'
        logging.info('Processing system calls for %s', _target)

        protofile_name = os.path.join(args.prototypes, f'{_os}_{_arch}_prototypes.txt')
        assert os.path.isfile(
            protofile_name
        ), f'Missing prototype file {protofile_name}'

        syscalls = global_context['syscalls'][_target]
        syscalls_arch = global_context['syscalls_arch'][_arch]
        target_context = {
            'arch': _arch,
            'os': _os,
            'syscalls': syscalls,
            'arch_conf': KNOWN_ARCH[_arch],
        }
        if _target in context_target_extra:
            d = context_target_extra[_target]
            assert all(
                k not in target_context for k in list(d.keys())
            ), f'target context for {_target} overwrites values'
            target_context |= d

        # Parse prototype file contents. Extra context is passed to set
        # properties that are not defined by the prototype definition.

        new_scs = {} # We use (name,args): syscall object with 1 or more nos

        with open(protofile_name) as protofile:
            for lineno, line in enumerate(protofile, 1):

                # HACK: we want to support multiple ABIs for the same arch. For MIPS
                # N32 + N64 we've seen distinct callnos with the same name and args.
                # As such, we expand this interface to support a many-to-one mapping
                # where multiple syscall numbers map to the same syscall object

                # If we ever encounter an arch with multiple ABIs that have distinct
                # arguments, we'll need to refactor this better.

                # First we parse the prototype line to get the callno and name
                fields = prototype_linere.match(line)
                if fields is None:
                    logging.debug('Bad prototype line in %s:%d: %s', protofile.name, lineno, line.rstrip())
                    continue
                sc_name = fields[3]

                new_syscall = SysCall(fields, target_context)
                new_args = str(new_syscall.args)

                if (new_syscall.name, new_args) not in new_scs:
                    new_scs[(new_syscall.name, new_args)] = new_syscall
                    syscalls.append(new_syscall)
                    syscalls_arch[sc_name] = new_syscall
                else:
                    # Already have a syscall object with this name and args, just add to nos
                    new_scs[(new_syscall.name, new_args)].nos.append(new_syscall.nos[0])
                    # And add args in case they're different, just for good soucre comments
                    this_args = new_syscall.args_raw[0]
                    if this_args not in new_scs[(new_syscall.name, new_args)].args_raw:
                        new_scs[(new_syscall.name, new_args)].args_raw.append(this_args)

        # Reformat into name: syscall mappings
        syscalls_to_write = {sc.name: sc for sc in syscalls}
        # Sort by smallest sc.nos values
        syscalls.sort(key=lambda sc: min(sc.nos))
        logging.info('Loaded %d system calls from %s.', len(syscalls), protofile_name)

        # Calculate the maximum number of arguments and system call number for this os/arch.
        target_context['max_syscall_args'] = max(len(s.args) for s in syscalls)
        target_context['max_syscall_no'] = max(max(s.nos) for s in syscalls)
        target_context['max_syscall_generic_no'] = max(
            max(s.nos) for s in syscalls if s.generic
        )

        # Update the global maximum number of arguments and system call number.
        global_context['global_max_syscall_args'] = max(
                global_context['global_max_syscall_args'], target_context['max_syscall_args'])
        global_context['global_max_syscall_no'] = max(
                global_context['global_max_syscall_no'], target_context['max_syscall_no'])
        global_context['global_max_syscall_generic_no'] = max(
                global_context['global_max_syscall_generic_no'], target_context['max_syscall_generic_no'])

        # Render per-target output files.
        j2tpl = j2env.get_template('syscall_switch_enter.tpl')
        with open(os.path.join(args.outdir, f"{args.prefix}syscall_switch_enter_{_os}_{_arch}.cpp"), "w+") as of:
            logging.info("Writing %s", of.name)
            of.write(j2tpl.render(target_context))
        j2tpl = j2env.get_template('syscall_switch_return.tpl')
        with open(os.path.join(args.outdir, f"{args.prefix}syscall_switch_return_{_os}_{_arch}.cpp"), "w+") as of:
            logging.info("Writing %s", of.name)
            of.write(j2tpl.render(target_context))

        # Generate syscall info dynamic libraries.
        if args.generate_info:
            j2tpl = j2env.get_template('syscalls_info.tpl')
            with open(os.path.join(args.outdir, f"{args.prefix}dso_info_{_os}_{_arch}.c"), "w+") as of:
                logging.info("Writing %s", of.name)
                of.write(j2tpl.render(target_context))

        arch_scs[_arch][_os] = syscalls_to_write
    
    for _arch in arch_scs:
        oss = sorted(arch_scs[_arch].keys())
        outvals = {}
        for _os in oss:
            for ov in arch_scs[_arch][_os]:
                outvals[ov] = arch_scs[_arch][_os][ov]
        
        # Make syscalls_ext_typedefs_[arch] files
        j2tpl = j2env.get_template('syscalls_ext_typedefs_arch.tpl')
        of_name = f'{args.prefix}syscalls_ext_typedefs_{_arch}.h'
        with open(os.path.join(args.outdir, of_name), 'w') as of:
            logging.info("Writing %s", of.name)
            of.write(j2tpl.render(syscalls=outvals))

    # Render big files.
    for tpl, ext in GENERATED_FILES:
        j2tpl = j2env.get_template(tpl)
        of_name = f'{args.prefix}{os.path.splitext(os.path.basename(tpl))[0]}{ext}'
        with open(os.path.join(args.outdir, of_name), 'w+') as of:
            logging.info("Writing %s", of.name)
            of.write(j2tpl.render(global_context))

# vim: set tabstop=4 softtabstop=4 expandtab :