"""
IDAPython Script to load ida_taint2 data and colorize basic blocks that contain
instructions that maninpulate tainted data.
"""

import csv

from PyQt5.QtWidgets import (QFileDialog, QInputDialog)

COLOR = 0x55AAFF

filename, _ = QFileDialog.getOpenFileName(None, "Open file", ".",
    "CSV Files(*.csv)")
if filename == "":
    exit(0)

selected_pid, ok = QInputDialog.getInt(None, "Process ID", "Enter Process ID")
if not ok:
    exit(0)

input_file = open(filename, "r")

reader = csv.reader(input_file)
# skip header
next(reader, None)
for row in reader:
    pid = int(row[0])
    pc = int(row[1])
    if pid != selected_pid:
        continue
    fn = idaapi.get_func(pc)
    if not fn:
        continue
    fc = idaapi.FlowChart(fn)
    bb = None
    for blk in fc:
        if blk.startEA <= pc and blk.endEA > pc:
           bb = blk
    while not (idaapi.is_call_insn(pc-1) or
               idaapi.is_ret_insn(pc-1) or
               idaapi.is_indirect_jump_insn(pc-1) or
               pc == bb.endEA):  
        SetColor(pc, CIC_ITEM, COLOR)
        pc += 1
input_file.close()
