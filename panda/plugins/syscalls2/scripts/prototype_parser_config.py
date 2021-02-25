import os

#
# Configuration for valid architectures/operating systems.
#
# Building the prototypes may vary between architectures, even for for
# the same operating system. For this, we use a flexible approach based
# on pluggable parsers. The parsers are specified in the configuation
# dictionary below. The results of the specified parsers are combined
# using write_prototypes() to produce the PANDA system call prototypes.
#
# Pluggable parsers:
#   - map_function_signature: Specifies the function/arguments that
#     can be used to acquire a [entry function name]->[signature]
#     mapping for the target system calls.
#   - map_function_number: Specifies the function/arguments that can
#     be used to acquire a [entry function name]->[number] mapping
#     for the target system calls. This allows direct mapping of
#     numbers to signatures.
#   - map_name_number: Specifies the function/arguments that can be
#     used to acquire a [name]->[number] mapping for the target system
#     calls. The name corresponds to to the name of an entry function.
#     This allows mapping of numbers to signatures after inferring the
#     entry function name from the system call name.
#
# Additional documentation for the implemented parser can be found in
# their definition.
#
# Other configuration values:
#   - bits: Target ISA bits, presumably also number of bits of a
#     long int.
#   - src: Root directory for scanned files.
#   - json_dir: Where to find json files to load.
#   - extrasigs: json file with additional signatures or signature
#     overrides.
#   - outfile: Override automatically generated configuration name.
#
# The configuration values listed in CONFIG_CLI_OVERRIDES can be
# overriden using command line arguments.
#


##############################################################################
### Linux config #############################################################
##############################################################################
CONFIG_LINUX = {
    'linux:x64:generic': {
        'bits': 64,
        'src': os.path.expanduser('~/git/ubuntu-bionic'),
        'map_function_signature': {
            'parser': 'parse_signature_files',
            'locations': {
                'include/linux/syscalls.h': r'asmlinkage (?P<signature>\w+\s+(?P<syscall>\w+)\(.*)',
                'arch/x86/include/asm/syscalls.h': r'(asmlinkage )?(?P<signature>\w+ (?P<syscall>\w+)\(.*)',
            },
            'normalize': True,
        },
        'map_function_number': {
            'parser': 'parse_numbers_tbl',
            'source': 'arch/x86/entry/syscalls/syscall_64.tbl',
        },
    },
    'linux:x86:ubuntu': {
        'bits': 32,
        'src': os.path.expanduser('~/git/ubuntu-bionic'),
        'map_function_signature': {
            'parser': 'parse_signature_files',
            'locations': {
                'include/linux/syscalls.h': r'asmlinkage (?P<signature>\w+\s+(?P<syscall>\w+)\(.*)',
                'arch/x86/include/asm/syscalls.h': r'(asmlinkage )?(?P<signature>\w+ (?P<syscall>\w+)\(.*)',
            },
            'normalize': True,
        },
        'map_function_number': {
            'parser': 'parse_numbers_tbl',
            'source': 'arch/x86/entry/syscalls/syscall_32.tbl',
        },
    },
    'linux:arm:ubuntu': {
        'bits': 32,
        'src': os.path.expanduser('~/git/ubuntu-bionic'),
        'extrasigs': 'linux_arm_extrasigs.json',
        'map_function_signature': {
            'parser': 'parse_signature_files',
            'locations': {
                'include/linux/syscalls.h': r'asmlinkage (?P<signature>\w+\s+(?P<syscall>\w+)\(.*)',
                'arch/arm/kernel/signal.c': r'asmlinkage (?P<signature>\w+\s+(?P<syscall>\w+)\(.*)',
            },
            'normalize': True,
        },
        'map_function_number': {
            'parser': 'parse_numbers_calltable',
            'source': 'arch/arm/kernel/calls.S',
            'regex': {
                'callnr': r'^/\*\s*(?P<nr>\d+)\s*\*/',
                'call': r'CALL\((?P<obsolete>OBSOLETE\()?(?P<abi>ABI\()?(?P<syscall>\w+)',
            },
            'syscalls_skip': ['sys_ni_syscall',],
        },
        'map_name_number': {
            'parser': 'parse_numbers_unistd',
            'source': 'arch/arm/include/uapi/asm/unistd.h',
            'cpp_flags': ['-D__ARM_EABI__', '-D__KERNEL__',],
        },
    },
    'linux:arm64:ubuntu': {
        'bits': 64,
        'src': os.path.expanduser('~/git/ubuntu-bionic'),
        #'extrasigs': 'linux_arm_extrasigs.json', # ???
        'map_function_signature': {
            'parser': 'parse_signature_files',
            'locations': {
                'include/linux/syscalls.h': r'asmlinkage (?P<signature>\w+\s+(?P<syscall>\w+)\(.*)',
                'arch/arm64/kernel/signal.c': r'asmlinkage (?P<signature>\w+\s+(?P<syscall>\w+)\(.*)',
            },
            'normalize': True,
        },
        'map_function_number': {
            'parser': 'parse_numbers_calltable',
            #'source': 'include/uapi/asm-generic/unistd.h',
            #'source': 'arch/arm64/include/asm/unistd32.h', # Just includes arch/arm64/include/uapi/asm/unistd.h
            'source': 'include/uapi/asm-generic/unistd.h',
            'regex': {
                'callnr': r'^/\*\s*(?P<nr>\d+)\s*\*/',
                'call': r'__(SYSCALL|SC_COMP)\(__NR[a-zA-Z_]*, (?P<compat>compat_)?(?P<syscall>\w+)',
               #'call': r'CALL\((?P<obsolete>OBSOLETE\()?(?P<abi>ABI\()?(?P<syscall>\w+)',
            },
            'syscalls_skip': [],
        },

        'map_name_number': {
            'parser': 'parse_numbers_unistd',
            #'source': 'arch/arm64/include/uapi/asm/unistd.h',
            #'source': 'arch/arm64/include/asm/unistd32.h',
            'source': 'include/uapi/asm-generic/unistd.h',
            'cpp_flags': ['-D__ARM_EABI__', '-D__KERNEL__', '-D__ARCH_WANT_RENAMEAT']
        },
    },
    # Generate using stock linux kernel at v5.8
    'linux:mips:generic': {
        'bits': 32,
        'src': os.path.expanduser('~/git/linux'),
        'map_function_signature': {
            'parser': 'parse_signature_files',
            'locations': {
                'include/linux/syscalls.h': r'asmlinkage (?P<signature>\w+\s+(?P<syscall>\w+)\(.*)',
                'arch/mips/kernel/signal.c': r'asmlinkage (?P<signature>\w+\s+(?P<syscall>\w+)\(.*)',
            },
            'normalize': True,
        },
        'map_function_number': {
            'parser': 'parse_numbers_tbl',
            'source': 'arch/mips/kernel/syscalls/syscall_o32.tbl',
        },
    },
    # Generate using Linux kernel at v2.6. Note the prototypes files for mips was hand-created
    # to merge the 2.6 and 5.8 prototypes so it should work on both and everything between
    'linux:mips26:generic': {
        'bits': 32,
        'src': os.path.expanduser('~/git/linux'), # XXX: If you change this be sure to change below
        'map_function_signature': {
            'parser': 'parse_signature_files',
            'locations': {
                'include/linux/syscalls.h': r'asmlinkage (?P<signature>\w+\s+(?P<syscall>\w+)\(.*)',
                'arch/mips/kernel/signal.c': r'asmlinkage (?P<signature>\w+\s+(?P<syscall>\w+)\(.*)',
            },
            'normalize': True,
        },
        'map_function_number': {
            'parser': 'parse_numbers_calltable',
            'source': 'arch/mips/kernel/scall32-o32.S',
            'regex': {
                'callnr': r'.*/\*\s*(?P<nr>\d+)\s*\*/$',
                'call': r'\tsys\t(?P<syscall>\w+)',
            },
            'syscalls_skip': ['sys_ni_syscall',],
        },
        'map_name_number': {
            'parser': 'parse_numbers_unistd',
            'source': 'arch/mips/include/asm/unistd.h',
            'cpp_flags': ['-D_MIPS_SIM=1', '-I'+os.path.expanduser("~/git/linux")+'/arch/mips/include'],
        },
    },
}

##############################################################################
### Windows config ###########################################################
##############################################################################
WINDOWS_VARIANTS = (
    ('win2000:x86:volatility', 'windows_2000_x86_prototypes.txt', 32),
    ('xp_sp2:x86:volatility', 'windows_xpsp2_x86_prototypes.txt', 32),
    ('xp_sp3:x86:volatility', 'windows_xpsp3_x86_prototypes.txt', 32),
    ('win2003_sp0:x86:volatility', 'windows_2003sp0_x86_prototypes.txt', 32),
    ('win2003_sp12:x64:volatility', 'windows_2003sp12_x64_prototypes.txt', 64),
    ('win2003_sp12:x86:volatility', 'windows_2003sp12_x86_prototypes.txt', 32),
    ('vista_sp0:x64:volatility', 'windows_vistasp0_x64_prototypes.txt', 64),
    ('vista_sp0:x86:volatility', 'windows_vistasp0_x86_prototypes.txt', 32),
    ('vista_sp12:x64:volatility', 'windows_vistasp12_x64_prototypes.txt', 64),
    ('vista_sp12:x86:volatility', 'windows_vistasp12_x86_prototypes.txt', 32),
    ('win7_sp01:x64:volatility', 'windows_7_x64_prototypes.txt', 64),
    ('win7_sp01:x86:volatility', 'windows_7_x86_prototypes.txt', 32),
    ('win8_sp0:x64:volatility', 'windows_8sp0_x64_prototypes.txt', 64),
    ('win8_sp0:x86:volatility', 'windows_8sp0_x86_prototypes.txt', 32),
    ('win8_sp1:x64:volatility', 'windows_8sp1_x64_prototypes.txt', 64),
    ('win8_sp1:x86:volatility', 'windows_8sp1_x86_prototypes.txt', 32),
)
CONFIG_WINDOWS = { s: {
    'bits': bits,
    'src': '../generated-in',
    'outfile': outfile,
    'map_function_signature': {
        'parser': 'parse_signature_files',
        'locations': {
            'all_windows_prototypes.txt': r'(?P<signature>\w+\s+(?P<syscall>\w+)\s*\(.*)',
        },
        'normalize': False,
    },
    'map_function_number': {
        'parser': 'parse_numbers_volatility',
    },
} for (s, outfile, bits) in WINDOWS_VARIANTS}

##############################################################################
### Config imported by main module ###########################################
##############################################################################
CONFIG = {}
CONFIG.update(CONFIG_LINUX)
CONFIG.update(CONFIG_WINDOWS)
CONFIG_CLI_OVERRIDES = ['src', 'json_dir', 'extrasigs',]

# vim: set tabstop=4 softtabstop=4 expandtab :
