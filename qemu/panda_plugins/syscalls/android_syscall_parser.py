"""
Output panda tool to parse system calls on Linux
"""

import re

ARM_CALLNO = "env->regs[7]"
ARM_ARGS = ["env->regs[0]", "env->regs[1]", "env->regs[2]", "env->regs[3]", "env->regs[4]", "env->regs[5]", "env->regs[6]"]
ARM_SP = "env->regs[13]"

X86_CALLNO = "EAX"
X86_ARGS = ["EBX", "ECX", "EDX", "ESI", "EDI", "EBP"]


types_64 = ["loff_t", 'u64']
types_32 = ["int", "long", "size_t", 'u32', 'off_t', 'timer_t', '__s32', 'key_t', 
            'key_serial_t', 'mqd_t', 'clockid_t', 'aio_context_t', 'qid_t', 'old_sigset_t', 'union semun']
types_16 = ['old_uid_t', 'uid_t', 'mode_t', 'gid_t', 'pid_t']
types_pointer = ['cap_user_data_t', 'cap_user_header_t', '...']

print "switch(", ARM_CALLNO, "){\n"


def copy_string(source, fname):
    print "log_string(%s, \"%s\");" % (source,fname)

def record_address(source, fname):
    print "log_pointer(%s, \"%s\");" %(source, fname)
    
def record_32(source, fname):
    print "log_32(%s, \"%s\");" %(source, fname)

def record_64(highsource, lowsource, fname):
    print "log_64(%s, %s, \"%s\");" %(highsource, lowsource, fname)
    
# Goldfish kernel doesn't support OABI layer. Yay!
with open("android_arm_syscall_prototypes") as armcalls:
    linere = re.compile("(\d+) (.+) (\w+)\((.*)\);")
    charre = re.compile("char.*\*")
    for line in armcalls:
        # Fields: <no> <return-type> <name><signature with spaces>
        fields = linere.match(line)
        callno = fields.group(1)
        rettype = fields.group(2)
        callname = fields.group(3)
        args = fields.group(4).split(',')
        print "//",callno, rettype, callname, args
        format = ""
        for arg in args:
            #print callno, rettype, callname, args
            argname = arg.split()[-1]
            if charre.search(arg) and not argname.endswith('buf') and argname != '...' and not argname.endswith('[]'):
                format += 's'
            elif '*' in arg or any([x in arg for x in types_pointer]):
                format += 'p'
            elif any([x in arg for x in types_64]):
                format += '8'
            elif any([x in arg for x in types_32]) or any([x in arg for x in types_16]):
                format += '4'
            elif arg.strip() == 'void':
                pass
            elif arg.strip() == 'unsigned' or (len(arg.split()) is 2 and arg.split()[0] == 'unsigned'):
                format += '4'
            else:
                print "unknown:", arg
        print "case", callno, ":"
        print "record_syscall(\"%s\");" % callname
        argno = 0
        for i, val in enumerate(format):
            if argno >= len(ARM_ARGS):
                print "// out of registers. Use the stack!"
                break
            if val == 's':
                copy_string(ARM_ARGS[argno], args[i])
            elif val == 'p':
                record_address(ARM_ARGS[argno], args[i])
            elif val == '4':
                record_32(ARM_ARGS[argno], args[i])
            elif val == '8':
                # alignment sadness. Linux tried to make sure none of these happen
                if (argno % 2) == 1:
                    print "// skipping arg for alignment"
                    argno+= 1
                    if argno >= len(ARM_ARGS):
                        print "// out of registers. Use the stack!"
                        break
                record_64(ARM_ARGS[argno], ARM_ARGS[argno+1],args[i])
                argno+=1
            argno+=1
        print "finish_syscall();"
        print "break;"
    print "default:"
    print "record_syscall(\"UNKNOWN\");"
    print "}"
        