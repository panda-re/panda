#!/usr/bin/env python3
'''
example_after_init.py

Registers the after_machine_init callback and prints "hit machine init" when
hit and the ends the analysis

Run with: python3 after_init.py
'''
from sys import argv
from pandare import Panda

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

@panda.cb_after_machine_init
def after_machine_init(cpu):
	print("Hit machine init. Shutdown analysis")
	panda.end_analysis()

panda.run()
