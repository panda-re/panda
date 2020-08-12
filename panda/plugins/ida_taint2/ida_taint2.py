"""
IDAPython Script to ingest an ida_taint2 report.
"""

import csv
import datetime

import ida_kernwin
import ida_loader
import ida_funcs
import ida_name
import ida_nalt
import ida_bytes

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QDialog, QPushButton, QTableWidget, QHeaderView, QAbstractItemView,
        QTableWidgetItem, QHBoxLayout, QVBoxLayout, QFileDialog, QMessageBox)

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
            process_name_item = QTableWidgetItem(p[0])
            process_name_item.setFlags(process_name_item.flags() & ~(Qt.ItemIsEditable))
            self.process_table.setItem(i, 0, process_name_item)
            process_id_item = QTableWidgetItem(str(p[1]))
            process_id_item.setFlags(process_id_item.flags() & ~(Qt.ItemIsEditable))
            self.process_table.setItem(i, 1, process_id_item)
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
            raise Exception("Supposedly impossible condition reached!")
        row = selectionModel.selectedRows()[0].row()
        return int(self.process_table.item(row, 1).data(0))


    @classmethod
    def selectProcess(cls, processes):
        psd = cls(processes)
        if QDialog.Accepted == psd.exec_():
            return psd.selectedProcess()
        return None

def read_semantic_labels(filename):
    semantic_labels = dict()
    try:
        with open(filename) as f:
            reader = csv.reader(f)
            for row in reader:
                semantic_labels[int(row[0])]=row[1]
    except IOError:
        pass
    except OSError:
        pass

    return semantic_labels

def main():
    filename, _ = QFileDialog.getOpenFileName(None, "Open file", ".", "CSV Files(*.csv)")
    if filename == "":
        return

    processes = set()
    input_file = open(filename, "r")
    reader = csv.reader(input_file)
    next(reader, None)
    for row in reader:
        processes.add((row[0], int(row[1])))
    input_file.close()

    selected_pid = ProcessSelectDialog.selectProcess(processes)
    # N.B.:  0 is a valid process ID
    if (None == selected_pid):
        return

    semantic_labels = read_semantic_labels(filename + ".semantic_labels")

    snapshot = ida_loader.snapshot_t()
    snapshot.desc = "Before ida_taint2.py @ %s" % (datetime.datetime.now())
    ida_kernwin.take_database_snapshot(snapshot)

    input_file = open(filename, "r")
    reader = csv.reader(input_file)
    labels_for_pc = {}
    # skip header
    next(reader, None)
    for row in reader:
        pid = int(row[1])
        pc = int(row[2], 16)
        label = int(row[3])

        try:
            label = semantic_labels[label]
        except KeyError:
            pass

        if pid != selected_pid:
            continue
        fn = ida_funcs.get_func(pc)
        if not fn:
            continue
        fn_start = fn.start_ea
        fn_name = ida_funcs.get_func_name(fn_start)
        if "TAINTED" not in fn_name:
            ida_name.set_name(fn_start, "TAINTED_" + fn_name, ida_name.SN_CHECK)
        fn.color = FUNC_COLOR
        ida_nalt.set_item_color(pc, INST_COLOR)
        if pc not in labels_for_pc:
            labels_for_pc[pc] = set()
        labels_for_pc[pc].add(label)
    input_file.close()

    for pc, labels in labels_for_pc.items():
        comment = ida_bytes.get_cmt(pc, 0)
        if not comment:
            comment = ""
        label_portion = "taint labels = {}".format(list(labels))
        if comment == "":
            comment = label_portion
        else:
            comment += ", " + label_portion
        ida_bytes.set_cmt(pc, comment, 0)        

if __name__ == "__main__":
    try:
        main()
    except ValueError as ve:
        msg = "Failed to read IDA Taint CSV: %s" % (ve)
        QMessageBox.critical(None, "Error", msg)
    except Exception as e:
        msg = "Unexpected error: %s" % (e)
        QMessageBox.critical(None, "Error", msg)
