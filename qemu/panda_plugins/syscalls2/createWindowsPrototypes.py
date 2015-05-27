#!/usr/bin/env python

from volatility.plugins.overlays.windows.vista_sp0_x64_syscalls import syscalls as vista_sp0_x64_syscalls
from volatility.plugins.overlays.windows.vista_sp0_x86_syscalls import syscalls as vista_sp0_x86_syscalls
from volatility.plugins.overlays.windows.vista_sp12_x64_syscalls import syscalls as vista_sp12_x64_syscalls
from volatility.plugins.overlays.windows.vista_sp12_x86_syscalls import syscalls as vista_sp12_x86_syscalls
from volatility.plugins.overlays.windows.win2003_sp0_x86_syscalls import syscalls as win2003_sp0_x86_syscalls
from volatility.plugins.overlays.windows.win2003_sp12_x64_syscalls import syscalls as win2003_sp12_x64_syscalls
from volatility.plugins.overlays.windows.win2003_sp12_x86_syscalls import syscalls as win2003_sp12_x86_syscalls
from volatility.plugins.overlays.windows.win7_sp01_x64_syscalls import syscalls as win7_sp01_x64_syscalls
from volatility.plugins.overlays.windows.win7_sp01_x86_syscalls import syscalls as win7_sp01_x86_syscalls
from volatility.plugins.overlays.windows.win8_sp0_x64_syscalls import syscalls as win8_sp0_x64_syscalls
from volatility.plugins.overlays.windows.win8_sp0_x86_syscalls import syscalls as win8_sp0_x86_syscalls
from volatility.plugins.overlays.windows.win8_sp1_x64_syscalls import syscalls as win8_sp1_x64_syscalls
from volatility.plugins.overlays.windows.win8_sp1_x86_syscalls import syscalls as win8_sp1_x86_syscalls
from volatility.plugins.overlays.windows.xp_sp2_x86_syscalls import syscalls as xp_sp2_x86_syscalls
from xp_sp3_x86_syscalls import syscalls as xp_sp3_x86_syscalls

tables = [
    (vista_sp0_x64_syscalls, "vista_sp0_x64"),
    (vista_sp0_x86_syscalls, "vista_sp0_x86"),
    (vista_sp12_x64_syscalls, "vista_sp12_x64"),
    (vista_sp12_x86_syscalls, "vista_sp12_x86"),
    (win2003_sp0_x86_syscalls, "win2003_sp0_x86"),
    (win2003_sp12_x64_syscalls, "win2003_sp12_x64"),
    (win2003_sp12_x86_syscalls, "win2003_sp12_x86"),
    (win7_sp01_x64_syscalls, "windows7_x64"),
    (win7_sp01_x86_syscalls, "windows7_x86"),
    (win8_sp0_x64_syscalls, "win8_sp0_x64"),
    (win8_sp0_x86_syscalls, "win8_sp0_x86"),
    (win8_sp1_x64_syscalls, "win8_sp1_x64"),
    (win8_sp1_x86_syscalls, "win8_sp1_x86"),
    (xp_sp2_x86_syscalls, "windowsxp_sp2_x86"),
    (xp_sp3_x86_syscalls, "windowsxp_sp3_x86"),
]

import sys

prototypes = {}
for line in open(sys.argv[1]):
    ret, name, args = line.strip().split(None, 2)
    prototypes[name] = (ret, args)

for syscalls, filename in tables:
    with open(filename + "_prototypes.txt", "w") as protofile:
        for i in range(len(syscalls)):
            for j in range(len(syscalls[i])):
                ordinal = i << 12 | j
                name = syscalls[i][j]
                if name in prototypes:
                    ret, args = prototypes[name]
                    print >>protofile, "%d %s %s %s" % (ordinal, ret, name, args)
                else:
                    print >>protofile, "%d missing %s" % (ordinal, name)
