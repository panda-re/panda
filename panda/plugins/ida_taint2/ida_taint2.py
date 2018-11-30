"""
IDAPython Script to load ida_taint2 data and colorize instructiions that
maninpulate tainted data.
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
    pc = int(row[1], 16)
    if pid != selected_pid:
        continue
    SetColor(pc, CIC_ITEM, COLOR)
input_file.close()
