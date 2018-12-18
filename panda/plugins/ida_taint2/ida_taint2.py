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
    tb_pc = int(row[1])
    tb_size = int(row[2])
    if pid != selected_pid:
        continue
    i = 0
    while tb_pc+i < tb_pc+tb_size:
        SetColor(tb_pc+i, CIC_ITEM, COLOR)
        i += 1
input_file.close()
