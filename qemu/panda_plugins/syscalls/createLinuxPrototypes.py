
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

from sys import argv, exit

if len(argv) < 2:
    print "ERROR: Need location of linux source as first arg!"
    exit(1)
LINUXSOURCE = argv[1]
ARCH = "arm" if len(argv) < 3 else argv[2]
# get numbers from arch/x86/include/asm/unistd.h
NUMSOURCE = LINUXSOURCE + "/arch/" + ARCH + "/include/asm/unistd.h"
# get names from ARCH/x86/kernel/calls.S
CALLTABLE = LINUXSOURCE + "/arch/" + ARCH + "/kernel/" + ("syscall_table_32.S" if ARCH == "x86" else "calls.S")
# get names from ARCH/x86/kernel/entry-common.S

# get signatures from include/linux/syscalls.h
SIGNATURES = LINUXSOURCE + "/include/linux/syscalls.h"

# from /scratch/aospkernel/goldfish/arch/arm/kernel/traps.c
# ARM syscall 0x9ffff0 is cmpxchg: ignore it!
#__ARM_NR_breakpoint
#__ARM_NR_cacheflush
#__ARM_NR_usr26
#__ARM_NR_usr32
#__ARM_NR_set_tls


# ARM also has a bunch of wrappers for fork, vfork, execve, clone, sigsuspend, rt_sigsuspend, sigreturn, rt_sigreturn, sigaltstack, statfs64, and fsatfs64

signatures = {}

signatures['sys_fork'] = 'unsigned long fork(void);'
signatures['sys_vfork'] = 'unsigned long vfork(void);'
signatures['sys_execve'] = 'unsigned long execve(const char *filename, char *const argv[], char *const envp[]);'
signatures['sys_clone'] = 'long clone(unsigned long clone_flags, unsigned long newsp, int __user *parent_tidptr, int tls_val, int __user *child_tidptr, struct pt_regs *regs);'
signatures['sys_sigsuspend'] = 'long sigsuspend(int restart, unsigned long oldmask, old_sigset_t mask);'
signatures['sys_rt_sigsuspend'] = 'int sys_rt_sigsuspend(sigset_t __user *unewset, size_t sigsetsize);'

signatures['sys_sigreturn'] = 'int sigreturn(void);'
signatures['sys_rt_sigreturn'] = 'int sigreturn(void);'
signatures['sys_sigaltstack'] = 'int do_sigaltstack(const stack_t __user *uss, stack_t __user *uoss);'
#signatures['sys_statfs64'] = 'unsigned long sys_fork(void);'
#signatures['sys_fstatgs64'] = 'unsigned long sys_fork(void);'

signatures['sys_sigaction'] = 'int sigaction(int sig, const struct old_sigaction __user *act, struct old_sigaction __user *oact);'
signatures['sys_arm_mremap'] = 'unsigned long arm_mremap(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr);'
signatures['sys_rt_sigaction'] = 'long rt_sigaction(int sig, const struct sigaction __user * act, struct sigaction __user * oact,  size_t sigsetsize);'
#loff_t is 64-bit
signatures['sys_arm_fadvise64_64'] = 'long sys_arm_fadvise64_64(int fd, int advice, loff_t offset, loff_t len);'
signatures['sys_mmap2'] = 'long do_mmap2(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff);'

import re
with open(SIGNATURES) as sigfile:
    inone = False
    namere = re.compile("\W(.+)\(")
    signature = None
    for line in sigfile:
        line = line.strip()
        if line.startswith('asmlinkage') and line.endswith(';'):
            # one liner
            signature = line.split(" ", 1)[1]
            callname = namere.search(signature).group(1)
            signatures[callname] = signature
        elif line.startswith('asmlinkage'):
            signature = line.split(" ", 1)[1]
            inone = True
        elif inone and line.endswith(';'):
            signature += line
            callname = namere.search(signature).group(1)
            signatures[callname] = signature.replace('\n', ' ')
            inone = False
        elif inone:
            signature += line


with open("proto_printer.cpp", 'w') as printer:
    printer.write('#include "%s"\n' % NUMSOURCE)
    printer.write("#include <stdio.h>\n")
    printer.write("int main(){\n")

    with open(CALLTABLE) as calltable:
        if ARCH == "x86":
            sysre = re.compile("\\.long ([a-zA-Z0-9_]+)")
        elif ARCH == "arm":
            sysre = re.compile("CALL\((.*)\)")
        else:
            print "ERROR: unknown arch {0}".format(ARCH)
            exit(1)
        abire = re.compile("ABI\((.*),.*\)")
        callno = 0

        for line in calltable:
            syscall = sysre.search(line)
            if syscall:
                callname = syscall.group(1)
                # for ABI(newcall, oldcall) always select newcall
                abiselect = abire.match(callname)
                if abiselect:
                    callname = abiselect.group(1)
                # for OBSOLETE(oldcall)  skip
                if callname.startswith("OBSOLETE"):
                    callno+=1
                    continue
                # for sys_ni_syscall, skip
                if callname == "sys_ni_syscall":
                    callno+=1
                    continue
                

                # now we have "sys_foo" and #define __NR_foo <number>
                # fixups for the syscalls that go through SP and register adjusting wrappers
                if callname.endswith('_wrapper'):
                    callname = callname[:-len('_wrapper')]
                realname = callname.split('_',1)[1]
                # fix all the syscalls where names don't quite match
                if realname == 'llseek' or realname == 'sysctl':
                    realname = "_" + realname
                if realname == 'select':
                    realname = "_new"+realname
                if realname.startswith('new'):
                    realname = realname[3:]

                nrdef = "__NR_" + realname
                #printer.write('printf("%d ",{0} );\n'.format(nrdef))
                printer.write('printf("%d ",{0} );\n'.format(callno))
                try:
                    printer.write('printf("%s\\n", \"{0}\");\n'.format(signatures[callname]))
                except KeyError:
                    print "Missing", callname
                callno +=1
        # now deal with the ARM syscalls:

        if ARCH == "ARM":
            printer.write('printf("%d ",{0} );\n'.format('__ARM_NR_breakpoint'))
            printer.write('printf("%s\\n",\"{0}\" ); \n'.format('long ARM_breakpoint(void);'))
            printer.write('printf("%d ",{0} );\n'.format('__ARM_NR_cacheflush'))
            printer.write('printf("%s\\n",\"{0}\" ); \n'.format('long ARM_cacheflush(unsigned long start, unsigned long end, unsigned long flags);'))
            printer.write('printf("%d ",{0} );\n'.format('__ARM_NR_usr26'))
            printer.write('printf("%s\\n",\"{0}\" ); \n'.format('long ARM_user26_mode(void);'))
            printer.write('printf("%d ",{0} );\n'.format('__ARM_NR_usr32'))
            printer.write('printf("%s\\n",\"{0}\" ); \n'.format('long ARM_usr32_mode(void);'))
            printer.write('printf("%d ",{0} );\n'.format('__ARM_NR_set_tls'))
            printer.write('printf("%s\\n",\"{0}\" ); \n'.format('long ARM_set_tls(unsigned long arg);'))
            printer.write('printf("%d ",{0} + 0xfff0 );\n'.format('__ARM_NR_BASE'))
            printer.write('printf("%s\\n",\"{0}\" ); \n'.format('int ARM_cmpxchg(unsigned long val, unsigned long src, unsigned long* dest);'))
            # branch through zero = bad!
            printer.write('printf("%d ",{0} );\n'.format('__ARM_NR_BASE'))
            printer.write('printf("%s\\n",\"{0}\" ); \n'.format('long ARM_null_segfault(void);'))

        printer.write("return 0; }\n")
