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

class LabelsCompressor:
    def __init__(self, have_semantic_labels):
        self._have_semantic_labels = have_semantic_labels
        
    def _semantic_label_sorter(self, item):
        # semantic labels are formatted <packet number>-<byte offset>
        # we want to sort first by packet number, then by byte offset
        parts = item.split("-")
        packet_num = int(parts[0])
        offset = int(parts[1])
        return (packet_num, offset)
    
    def _append_semantic_label(self, labels, first):
        if (len(labels) > 0):
            groupsep = ", "
            lastlf = labels.rfind("\n")
            # lastlf will be -1 if none found, but that won't mess up the formatting
            if ((len(labels) - lastlf) > 50):
                groupsep = ",\n"
            updated_labels = labels + groupsep + str(first[0]) + ":" + str(first[1])
        else:
            updated_labels = str(first[0]) + ":" + str(first[1])
        return updated_labels
    
    def _append_semantic_label_range(self, labels, first, last):
        if (len(labels) > 0):
            groupsep = ", "
            lastlf = labels.rfind("\n")
            if ((len(labels) - lastlf) > 50):
                groupsep = ",\n"
            updated_labels = labels + groupsep + str(first[0]) + ":" + str(first[1]) + "-" + str(last[1])
        else:
            updated_labels = str(first[0]) + ":" + str(first[1]) + "-" + str(last[1])
        return updated_labels
        
    def _compress_sorted_semantic_labels(self, labels):
        clabels = ""
        first = None
        last = None
        for item in labels:
            itemparts = self._semantic_label_sorter(item)
            if (None == first):
                first = itemparts
            elif (None == last):
                if (first[0] == itemparts[0]):
                    if ((first[1]+1) == itemparts[1]):
                        last = itemparts
                    else:
                        clabels = self._append_semantic_label(clabels, first)
                        first = itemparts
                else:
                    clabels = self._append_semantic_label(clabels, first)
                    first = itemparts
            elif (last[0] == itemparts[0]):
                if ((last[1]+1) == itemparts[1]):
                    last = itemparts
                else:
                    clabels = self._append_semantic_label_range(clabels, first, last)
                    first = itemparts
                    last = None
            else:
                clabels = self._append_semantic_label_range(clabels, first, last)
                first = itemparts
                last = None
        if (None == last):
            clabels = self._append_semantic_label(clabels, first)
        else:
            clabels = self._append_semantic_label_range(clabels, first, last)
        return clabels
        
    def _compress_sorted_standard_labels(self, labels):
        clabels = ""
        lastline = ""
        first = None
        last = None
        for item in labels:
            if (0 == len(clabels)):
                # very first label
                clabels = str(item)
                lastline = str(item)
                first = item
            elif (None == last):
                if ((first + 1) == item):
                    # part of a consecutive sequence starting at first
                    last = item
                else:
                    # first did not start a consecutive sequence
                    if (len(lastline) > 50):
                        clabels = clabels + ",\n" + str(item)
                        lastline = str(item)
                    else:
                        clabels = clabels + ", " + str(item)
                        lastline = lastline + ", " + str(item)
                    first = item
            elif ((last + 1) == item):
                # item extends the consecutive sequence from last
                last = item
            else:
                # the previous last ended a consecutive sequence
                if (len(lastline) > 50):
                    clabels = clabels + "-" + str(last) + ",\n" + str(item)
                    lastline = str(item)
                else:
                    clabels = clabels + "-" + str(last) + ", " + str(item)
                    lastline = lastline + "-" + str(last) + ", " + str(item)
                first = item
                last = None
        if (last is not None):
            # last label ends a consecutive sequence
            clabels = clabels + "-" + str(last)
        return clabels
        
    def compress_labels(self, labels):
        if (self._have_semantic_labels):
            sorted_labels = sorted(labels, key=self._semantic_label_sorter)
            compressed_labels = self._compress_sorted_semantic_labels(sorted_labels)
        else:
            sorted_labels = sorted(labels, key=int)
            compressed_labels = self._compress_sorted_standard_labels(sorted_labels)
        return compressed_labels
        
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

def skip_csv_header(reader, show_metadata):
    # newer ida_taint2 output files have some metadata before the header
    line1 = next(reader, None)
    if (line1[0].startswith("PANDA Build Date")):
        exec_time = next(reader, None)
        if (show_metadata):
            idaapi.msg(line1[0] + ":  " + line1[1] + "\n")
            idaapi.msg(exec_time[0] + ":  " + exec_time[1] + "\n")
        next(reader, None)
        
def main():
    filename, _ = QFileDialog.getOpenFileName(None, "Open file", ".", "CSV Files(*.csv)")
    if filename == "":
        return

    processes = set()
    input_file = open(filename, "r")
    reader = csv.reader(input_file)
    
    skip_csv_header(reader, True)
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
    skip_csv_header(reader, False)
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

    labels_compressor = LabelsCompressor(len(semantic_labels)>0)
    for pc, labels in labels_for_pc.items():
        comment = ida_bytes.get_cmt(pc, 0)
        if not comment:
            comment = ""
        compressed_labels = labels_compressor.compress_labels(labels)
        label_portion = "taint labels = " + compressed_labels
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
