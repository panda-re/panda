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

    seen = {} # name -> [entry details]
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
            if sys_name.startswith("do_"): # Unify names
                sys_name = sys_name.replace("do_", "")

            if sys_name.startswith("*"): # Parser put type into name
                sys_name = sys_name.replace("*", "")

            if sys_name not in seen:
                seen[sys_name] = []
            seen[sys_name].append(line)

            syscalls[sys_name] = sys_no
            num_sc[sys_no] = sys_name

    # Duplicates only show up in FreeBSD. It seems like we want to generally take the maximum value we see
    # though this will cause some issues for older OSes. Is there a way to get the OS version -> syscall name details
    # and then incorporate those?

    # Print a warning, then drop all but the highest number
    for name, dups in seen.items():
        if len(dups) > 1:
            print(f"WARNING dupliate entries for {name}:\n\t" + '\t'.join([x for x in dups]))

            nums = [x for x,s_name in num_sc.items() if s_name == name]
            non_max = [x for x in nums if x != max(nums)]
            for x in non_max:
                del num_sc[x]

    return num_sc

if __name__ == '__main__':
    results = {}
    for arch in ['linux_arm', 'linux_mips', 'linux_x64', 'linux_x86', 'freebsd_x64']:
        results[arch] = gen_syscalls(arch)
    with open("syscalls.json", 'w') as f:
        json.dump(results, f)
