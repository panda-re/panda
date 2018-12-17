"""
IDAPython Script to ingest an ida_taint2 report.
"""

import csv

from PyQt5.QtWidgets import *

FUNC_COLOR = 0x90EE90
INST_COLOR = 0x55AAFF

class ProcessSelectDialog(QDialog):
    def __init__(self, processes):
        super(ProcessSelectDialog, self).__init__()
        
        self.setWindowTitle("Select Process")
        
        btn_ok = QPushButton("OK")
        btn_ok.clicked.connect(self.accept)
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(2)
        self.process_table.setHorizontalHeaderLabels(("Process Name", "PID"))
        self.process_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.process_table.setRowCount(len(processes))
        self.process_table.verticalHeader().setVisible(False)
        self.process_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.process_table.setSelectionMode(QAbstractItemView.SingleSelection)
        i = 0
        for p in processes:
            self.process_table.setItem(i, 0, QTableWidgetItem(p[0]))
            self.process_table.setItem(i, 1, QTableWidgetItem(p[1]))
            i += 1

        hbox = QHBoxLayout()
        hbox.addStretch(1)
        hbox.addWidget(btn_ok)
        hbox.addWidget(btn_cancel)

        vbox = QVBoxLayout()
        vbox.addWidget(self.process_table)
        vbox.addLayout(hbox)

        self.setLayout(vbox)

    def selectedProcess(self):
        selectionModel = self.process_table.selectionModel()
        if not selectionModel.hasSelection():
            return None
        if len(selectionModel.selectedRows()) > 1:
            print("should not be possible")
            exit(1)
        row = selectionModel.selectedRows()[0].row()
        return int(self.process_table.item(row, 1).data(0))
        

    @classmethod
    def selectProcess(cls, processes):
        psd = cls(processes)
        if QDialog.Accepted == psd.exec_():
            return psd.selectedProcess()
        return None

filename, _ = QFileDialog.getOpenFileName(None, "Open file", ".", "CSV Files(*.csv)")
if filename == "":
    exit(0)
    
processes = set()
input_file = open(filename, "r")
reader = csv.reader(input_file)
next(reader, None)
for row in reader:
    processes.add((row[0], row[1]))
input_file.close()

selected_pid = ProcessSelectDialog.selectProcess(processes)
if not selected_pid:
    exit(0)

input_file = open(filename, "r")
reader = csv.reader(input_file)
labels_for_pc = {}
# skip header
next(reader, None)
for row in reader:
    pid = int(row[1])
    pc = int(row[2], 16)
    label = int(row[3])
    if pid != selected_pid:
        continue
    fn = idaapi.get_func(pc)
    if not fn:
        continue
    fn_start = fn.startEA
    fn_name = GetFunctionName(fn_start)
    if "TAINTED" not in fn_name:
        MakeName(fn_start, "TAINTED_" + fn_name)
    SetColor(pc, CIC_FUNC, FUNC_COLOR)
    SetColor(pc, CIC_ITEM, INST_COLOR)
    if pc not in labels_for_pc:
        labels_for_pc[pc] = set()
    labels_for_pc[pc].add(label)
input_file.close()

for pc, labels in labels_for_pc.iteritems():
    comment = Comment(pc)
    if not comment:
        comment = ""
    label_portion = "taint labels = {}".format(list(labels))
    if comment == "":
        comment = label_portion
    else:
        comment += ", " + label_portion
    MakeComm(pc, comment)
