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
# *
# * This work is licensed under the terms of the GNU GPL, version 2.
# * See the COPYING file in the top-level directory.
# *
#PANDAENDCOMMENT */

''' PANDA tool for generating system call prototypes using various 
    sources.

    This is not an exact science. We try to make this script
    flexible to extend for more vendors, and operating systems.
    See MAINTENANCE.md for details. Also, carefuly read the comments
    above the configuration dictionary below.
'''

import sys
import os
import re
import ast
import json
import shlex
import subprocess
import logging
import argparse
import importlib
import inspect
from pprint import pprint, pformat


##############################################################################
### Definitions and configuration ############################################
##############################################################################
# Setup logging first thing in the morning.
LOGLEVEL = logging.INFO
logging.basicConfig(format='%(levelname)s: %(message)s', level=LOGLEVEL)
from prototype_parser_config import CONFIG, CONFIG_CLI_OVERRIDES


##############################################################################
### Parser functions #########################################################
##############################################################################
def parse_signature_files(rootdir, arch, locations, normalize=False):
    ''' Parse system call signatures from different source files.
        Lines in the files are scanned to check for the start of a
        system call function declaration. If the declaration spans
        multiple lines, they are joined to get the whole declaration in
        a one-line string. Optionally, the signature is beautified.
    '''
    signatures_parsed = {}
    for source, regex in locations.items():
        sigfile = '%s/%s' % (rootdir, source)
        sigstart_re = re.compile(regex)
        logging.info('Parsing signatures from %s:', sigfile)
        assert os.path.isfile(sigfile)
        with open(sigfile) as f:
            multiline_signature = False
            for ln, line in enumerate(f, 1):
                line = line.strip()
                line_match = sigstart_re.search(line)
                if line_match is not None:
                    assert not multiline_signature
                    syscall = line_match.group('syscall')
                    signature = line_match.group('signature')
                    if line.endswith(')'):
                        ## function definition
                        signatures_parsed[syscall] = signature + ';'
                    elif line.endswith(';'):
                        ## function declaration - one liner
                        signatures_parsed[syscall] = signature
                    else:
                        ## function declaration - start multiline
                        multiline_signature = True
                elif multiline_signature and not line.endswith(';'):
                    # continue multiline
                    signature += line
                elif multiline_signature and line.endswith(';'):
                    # end multiline
                    signature += line
                    multiline_signature = False
                    signatures_parsed[syscall] = signature
                elif line != '':
                    #logging.debug('Skipping line %03d: \'%s\'', ln, line)
                    continue

    # normalize signatures
    # XXX: We could also strip unwanted qualifiers from signatures here.
    if normalize:
        for syscall, signature in signatures_parsed.items():
            signature = ' '.join(signature.split())
            signature = ', '.join([t.strip() for t in signature.split(',')])
            signature = re.sub(r'\*\s(\w+)(?=[,)])', r'*\1', signature)
            signature = signature.replace(' (', '(', 1)
            signatures_parsed[syscall] = signature

    logging.info('Parsed %d signatures from %s:', len(signatures_parsed), sigfile)
    return signatures_parsed

def parse_numbers_tbl(rootdir, arch, source):
    ''' Creates an [entry function]->[number] mapping for the system
        calls from a .tbl definition file.
        These files are used by Ubuntu to generate the actual system
        call headers at compile-time. When available, this is the
        preferred (and most robust way) way to create the PANDA
        system call prototype files.
    '''
    tblfile = '%s/%s' % (rootdir, source)
    logging.info('Parsing syscall numbers from %s.', tblfile)
    assert os.path.isfile(tblfile)
    syscall_numbers = {}
    with open(tblfile) as f:
        for ln, line in enumerate(f):
            if not re.match('^\d', line): continue
            nr, abi, name, entry, compat = pad_list(line.split(), 5)
            if entry is None:
                logging.warning('Ignoring system call %s (nr=%d) because no entry point is specified.', name, int(nr))
                continue
            # use the entry point name instead of the raw call name
            syscall_numbers[entry] = int(nr)
    return syscall_numbers

def parse_numbers_calltable(rootdir, arch, source, regex, syscalls_skip):
    ''' Creates a [entry function]->[number] mapping for the system
        calls from a system call table file.
        Some entry functions may bot be listed in the system call
        table file. So additional sources may need to be used in
        order to generate PANDA prototypes for all system calls.
    '''
    calltablefile = '%s/%s' % (rootdir, source)
    logging.info('Parsing syscall numbers from %s.', calltablefile)
    assert os.path.isfile(calltablefile), "Missing file " + calltablefile

    # parse numbers from file
    syscall_numbers = {}
    with open(calltablefile) as f:
        callnr_re = re.compile(regex['callnr'])
        call_re = re.compile(regex['call'])

        callnr = 0
        for ln, line in enumerate(f, 1):
            # extract call information
            # using groupdict()/get() acounts for missing group names
            call_m = call_re.search(line)
            if call_m:
                d = call_m.groupdict()
                syscall = d.get('syscall')
                is_abi = d.get('abi') is not None
                is_obsolete = d.get('obsolete') is not None
                is_compat = d.get('compat') is not None
            else:
                #logging.debug('Skipping line %03d: \'%s\'', ln, line)
                continue

            # Do we need to special case 'compat' syscalls?
            #if is_compat:
            #    logging.warning("COMPAT %s on line %d:", syscall, ln)

            # skip matching line
            if is_obsolete:
                logging.debug('Skipping obsolete syscall %s on line %d.', syscall, ln)
                callnr += 1
                continue
            elif syscall in syscalls_skip:
                logging.debug('Skipping syscall %s on line %d.', syscall, ln)
                callnr += 1
                continue

            # normalize names of syscalls that go through SP and register adjusting wrappers
            syscall = re.sub(r'_wrapper$', '', syscall)

            # scan for call number hint
            callnr_m = callnr_re.match(line)
            if callnr_m:
                callnr = int(callnr_m.group('nr'))
                #logging.debug('Call number set to %d on line %d.', callnr, ln)

            # add to dictionary
            syscall_numbers[syscall] = callnr
            callnr += 1
    return syscall_numbers

def parse_numbers_unistd(rootdir, arch, source, cpp_flags=[]):
    ''' Creates a [name]->[number] mapping for the system calls from
        a unistd.h-like header file. In order to produce the PANDA
        system call prototype files, the names have to be matched
        (heuristically) to entry function names.
    '''
    unistdfile = '%s/%s' % (rootdir, source)
    logging.info('Parsing syscall numbers from %s.', unistdfile)
    assert os.path.isfile(unistdfile)

    # scan number definitions
    syscall_nrdefs = {}
    with open(unistdfile) as f:
        for ln, line in enumerate(f, 1):
            if not re.match('^#define', line): continue
            define, macro, value = pad_list(line.split(None, 2), 3)
            if value is None:
                continue
            elif macro.startswith('__NR_'):
                syscall_name = re.sub(r'^__NR__?', '', macro)   # extra '_' accounts for _llseek
            elif macro.startswith('__%s_NR_' % (arch.upper())):
                syscall_name = re.sub(r'^__%s_NR_' % (arch.upper()), '%s_' % (arch.upper()), macro)
            else:
                continue
            syscall_nrdefs[syscall_name] = macro

    # construct a pseudo-header to feed to preprocessor
    header = '#include "%s"\n%s\n' % (unistdfile,
            '\n'.join(['%s:%s' % (n, m) for n, m in syscall_nrdefs.items()]))

    # use gcc to expand macros in the header
    cpp_flags = ' '.join(cpp_flags)
    cpp_cmd = 'gcc %s -E -' % (cpp_flags)
    cpp = subprocess.run(shlex.split(cpp_cmd), input=header,
            stdout=subprocess.PIPE, encoding='utf-8', check=True)

    # evaluate syscall numbers and return
    syscall_numbers = {}
    for line in cpp.stdout.splitlines():
        if len(line.strip())==0 or line.startswith('#'): continue
        try:
            syscall_name, syscall_nr_expr = pad_list(line.split(':', 1), 1)
        except ValueError:
            print("Failed to parse: " + line)
            raise
        if syscall_nr_expr is None: continue
        try:
            syscall_nr = ast.literal_eval(syscall_nr_expr)
            syscall_numbers[syscall_name] = syscall_nr
        except ValueError:
            logging.debug('Could not expand value "%s" for syscall %s.', syscall_nr, syscall_name)
            continue

    # return
    return syscall_numbers

def parse_numbers_volatility(rootdir, arch, os):
    ''' Reads system call lists from a custom package mirroring the
        system call overlays from the Volatility project.
    '''
    volatility_module = 'volatility_local.%s_%s_syscalls' % (os, arch)
    module = importlib.import_module(volatility_module)
    syscalls = module.syscalls
    syscall_numbers = {}
    for table_nr, table in enumerate(syscalls):
        for syscall_tnr, syscall_name in enumerate(table):
            syscall_nr = table_nr << 12 | syscall_tnr
            syscall_numbers[syscall_name] = syscall_nr
    del module
    return syscall_numbers


##############################################################################
### Helper functions #########################################################
##############################################################################
def pad_list(l, n, padding=None):
    ''' Pads a list to the specified length.
        Useful for parsing lines with a variable number of fields.
    '''
    assert type(l) is list
    padding_len = n - len(l)
    if padding_len > 0:
        l.extend([padding,] * padding_len)
    return l

def reverse_dict(d):
    ''' Return a dictionary that reverses the key-value mapping.
    '''
    assert type(d) is dict
    nd = {}
    for k, v in d.items():
        if v in nd:
            logging.warning('Reversing dictionary with duplicate items: d[%s] = d[%s] = %s', nd[v], k, v)
        nd[v] = k
    return nd

def run_parser(config, parser_name):
    ''' Executes a parser function.
        We need this wrapper because parser functions are defined after
        the configuration dictionary.
    '''
    assert config[parser_name]['parser'] in globals()
    parser = globals()[config[parser_name]['parser']]
    args = (config['src'], config['arch'])
    kwargs = {}

    for kwarg in inspect.getfullargspec(parser).args[2:]:
        if kwarg in config[parser_name]:
            kwargs[kwarg] = config[parser_name][kwarg]
        elif kwarg in config:
            kwargs[kwarg] = config[kwarg]
        else:
            raise TypeError('Missing keyword argument \'%s\' for %s().' % (kwarg, parser.__name__))

    logging.debug('%s(args=%s, kwargs=%s)', config[parser_name]['parser'], args, kwargs)
    return parser(*args, **kwargs)

def write_prototypes(fsigs, fnums, nnums, config, outdir):
    ''' Writes prototypes starting by iterating syscall_numbers and
        looking for an appropriate signature in syscall_signatures.
    '''
    assert(fsigs is not None and len(fsigs)), "No functions provided (incorrect map_name_number logic?)"
    assert(fnums is not None and len(fnums)), "No syscall numbers provided (incorrect map_function_number logic?)"
    if 'outfile' in config:
        protofile = '%s/%s' % (outdir, config['outfile'])
    else:
        protofile = '%s/%s_%s_prototypes.txt' % (outdir, config['os'], config['arch'])
    logging.info('Writing prototypes for %s:%s to %s.', config['os'], config['arch'], protofile)

    # work on a copy of fsigs, and reverse number mappings
    fsigs = fsigs.copy()
    fnums_r = reverse_dict(fnums)
    nnums_r = reverse_dict(nnums) if nnums is not None else {}

    # store results here
    numsigs = {}

    # directly match numbers from fnums_r to signatures
    for number, function in sorted(fnums_r.items()):
        # sidestep ptregs issue
        foo = re.search("(.*)/ptregs", function)
        if foo:
            function = foo.groups()[0]            
        if function in fsigs:
            numsigs[number] = fsigs[function]
            fsigs.pop(function)
            fnums_r.pop(number)
            nnums_r.pop(number, None)   # number may not exist
        else:
            logging.error('Could not find signature for %s (nr=%d).', function, number)
            continue

    # attempt to match numbers remaining in nnums_r to signatures
    for number, name in sorted(nnums_r.items()):
        syscall_prefixes = ['', 'sys_', 'ptregs_']
        for p in syscall_prefixes:
            function = '%s%s' % (p, name)
            if function in fsigs:
                numsigs[number] = fsigs[function]
                fsigs.pop(function)
                fnums_r.pop(number, None)   # number may not exist
                nnums_r.pop(number)
                break

    logging.debug(pformat({'fnums_r': fnums_r, 'nnums_r': nnums_r, 'fsigs': fsigs}, indent=2))

    # write collected data
    with open(protofile, 'w') as f:
        for number, signature in sorted(numsigs.items()):
            print('%d %s' % (number, signature), file=f)
        logging.info('Wrote %d prototypes to %s.', len(numsigs), protofile)

##############################################################################
### Main #####################################################################
##############################################################################
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PANDA syscall scanner.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--outdir', '-o', default='../generated-in', help='Output directory for syscall prototypes.')
    parser.add_argument('--target', '-t', choices=CONFIG.keys(), required=True, help='Configuration to use as an os:arch:variant triplet.')

    # config override options
    parser.add_argument('--src', '-s', help='Non-default kernel source directory.')
    parser.add_argument('--json-dir', default='../generated-in', help='Where to find any json files needed.')
    parser.add_argument('--extrasigs', help='json file with additional signatures.')

    # parse args and apply overrides
    args = parser.parse_args()
    config = CONFIG[args.target]
    config['os'], config['arch'], config['variant'] = args.target.split(':')
    for k in CONFIG_CLI_OVERRIDES:
        v = getattr(args, k)
        if v is not None:
            config[k] = v

    # sanity checks
    logging.debug('args: %s', args)
    logging.debug('config: %s', config)
    assert os.path.isdir(args.outdir), 'Output directory %s does not exist.' % args.outdir

    logging.info('Generating prototypes for {os}:{arch} using {variant} as source.'.format(**config))

    # run base parsers
    syscall_fsigs, syscall_fnums, syscall_nnums = (
            run_parser(config, p) if p in config else None
            for p in ['map_function_signature', 'map_function_number', 'map_name_number'])

    # load extra signatures
    if 'extrasigs' in config:
        with open('%s/%s' % (config['json_dir'], config['extrasigs'])) as f:
            extrasigs = json.load(f)
            syscall_fsigs.update(extrasigs)
            logging.info('Loaded %d additional signatures from %s.', len(extrasigs), config['extrasigs'])

    write_prototypes(syscall_fsigs, syscall_fnums, syscall_nnums, config, args.outdir)
    sys.exit(0)

    # Additional ARM stuff that may need adjustment.
    #
    # ARM also has a bunch of wrappers for fork, vfork, execve, clone,
    # sigsuspend, rt_sigsuspend, sigreturn, rt_sigreturn, sigaltstack,
    # statfs64, and fsatfs64
    #
    #if ARCH == "ARM":
    #printer.write('printf("%d ",{0} );\n'.format('__ARM_NR_breakpoint'))
    #printer.write('printf("%s\\n",\"{0}\" ); \n'.format('long ARM_breakpoint(void);'))
    #printer.write('printf("%d ",{0} );\n'.format('__ARM_NR_cacheflush'))
    #printer.write('printf("%s\\n",\"{0}\" ); \n'.format('long ARM_cacheflush(unsigned long start, unsigned long end, unsigned long flags);'))
    #printer.write('printf("%d ",{0} );\n'.format('__ARM_NR_usr26'))
    #printer.write('printf("%s\\n",\"{0}\" ); \n'.format('long ARM_user26_mode(void);'))
    #printer.write('printf("%d ",{0} );\n'.format('__ARM_NR_usr32'))
    #printer.write('printf("%s\\n",\"{0}\" ); \n'.format('long ARM_usr32_mode(void);'))
    #printer.write('printf("%d ",{0} );\n'.format('__ARM_NR_set_tls'))
    #printer.write('printf("%s\\n",\"{0}\" ); \n'.format('long ARM_set_tls(unsigned long arg);'))
    #printer.write('printf("%d ",{0} + 0xfff0 );\n'.format('__ARM_NR_BASE'))
    #printer.write('printf("%s\\n",\"{0}\" ); \n'.format('int ARM_cmpxchg(unsigned long val, unsigned long src, unsigned long* dest);'))
    ## branch through zero = bad!
    #printer.write('printf("%d ",{0} );\n'.format('__ARM_NR_BASE'))
    #printer.write('printf("%s\\n",\"{0}\" ); \n'.format('long ARM_null_segfault(void);'))

# vim: set tabstop=4 softtabstop=4 expandtab :
