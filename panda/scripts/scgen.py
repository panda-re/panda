#!/usr/bin/env python3

'''
Reformat the syscalls2 prototypes to a mapping from callno to syscall name
and store the results in syscalls.json in the following format:
    {
        'linux_arm':
            {
              '0': 'some_syscall',
              '1': 'another_syscall'
            },
        'linux_mips':
            {
              ...
            }
    }

Unfortunately syscall number keys are stored as strings
'''


import glob
import json
from os import path

base = path.join(path.dirname(__file__), "../plugins/syscalls2/generated-in/")

def gen_syscalls(os_arch):
    syscalls = {}
    num_sc = {}

    fname = f"{os_arch}_prototypes.txt"
    target = path.join(base, fname)
    if not path.isfile(target):
        raise ValueError(f"Unsupported os_arch: {os_arch} - could not find {target}")

    with open(target) as f:
        for line in f.readlines():
            if not len(line):
                continue

            # num type name(args
            try:
                sys_no = int(line.split(" ")[0])
            except:
                continue
            sys_name = line.split(" ")[2].split("(")[0]

            sys_name = sys_name.replace("sys_", "")
            if sys_name.startswith("do_"):
                sys_name.replace("do_", "")
            syscalls[sys_name] = sys_no
            num_sc[sys_no] = sys_name

    #return syscalls
    return num_sc

if __name__ == '__main__':
    results = {}
    for arch in ['linux_arm', 'linux_mips', 'linux_x64', 'linux_x86']:
        results[arch] = gen_syscalls(arch)
    with open("syscalls.json", 'w') as f:
        json.dump(results, f)
