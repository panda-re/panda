"""
IDAPython Script to ingest a coverage PANDA plugin report.
"""

import csv
import datetime

import ida_bytes
import ida_funcs
import ida_kernwin
import ida_loader
import ida_nalt

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QAbstractItemView, QCheckBox, QDialog, \
    QFileDialog, QHBoxLayout, QHeaderView, QPushButton, QTableWidget, \
    QTableWidgetItem, QVBoxLayout

FUNC_COLOR = 0x90EE90
INST_COLOR = 0x55AAFF

class ProcessSelectDialog(QDialog):
    def __init__(self, processes, initial_process, title, headers, has_tid):
        super(ProcessSelectDialog, self).__init__()
        
        self.setWindowTitle(title)
        
        self.seq_chkbx = QCheckBox("Sequence Labels")
        self.seq_chkbx.setChecked(True)
        
        # so can more easily prevent errors when omit this checkbox from GUI
        # create it whether or not we need it
        self.tid_chkbx = QCheckBox("Thread ID Labels")
        if (has_tid):
            self.tid_chkbx.setChecked(True)
        else:
            self.tid_chkbx.setChecked(False)
        
        btn_ok = QPushButton("OK")
        btn_ok.clicked.connect(self.accept)
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(2)
        self.process_table.setHorizontalHeaderLabels(headers)
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
        self.process_table.sortItems(0)
        if (initial_process is not None):
            matches = self.process_table.findItems(initial_process, Qt.MatchExactly)
            if (len(matches) > 0):
                self.process_table.setCurrentItem(matches[0])
        chkboxes = QVBoxLayout()
        chkboxes.addWidget(self.seq_chkbx)
        if (has_tid):
            chkboxes.addWidget(self.tid_chkbx)
        
        hbox = QHBoxLayout()
        hbox.addStretch(1)
        hbox.addWidget(btn_ok)
        hbox.addWidget(btn_cancel)

        vbox = QVBoxLayout()
        vbox.addWidget(self.process_table)
        vbox.addLayout(chkboxes)
        vbox.addLayout(hbox)

        self.setLayout(vbox)

    def selectedProcess(self):
        selection_model = self.process_table.selectionModel()
        if not selection_model.hasSelection():
            return None
        if len(selection_model.selectedRows()) > 1:
            raise Exception("Supposedly impossible condition reached!")
        row = selection_model.selectedRows()[0].row()
        return int(self.process_table.item(row, 1).data(0))

    def isAddSequenceLabels(self):
        return self.seq_chkbx.isChecked()
        
    def isAddThreadIDLabels(self):
        return self.tid_chkbx.isChecked()
        
    @classmethod
    def selectProcess(cls, processes, initial_process, title, headers, has_tid):
        psd = cls(processes, initial_process, title, headers, has_tid)
        if QDialog.Accepted == psd.exec_():
            seqs = psd.isAddSequenceLabels()
            tids = False
            if (has_tid):
                tids = psd.isAddThreadIDLabels()
            sel_id = psd.selectedProcess()
            return {'add_seqs':seqs, 'add_tids':tids, 'selected_id':sel_id}
        return None
        
def color_blocks(fn, pc, size):
    fn_start = fn.start_ea
    fn_name = ida_funcs.get_func_name(fn_start)
    if ("COVERED_" not in fn_name):
        ida_name.set_name(fn_start, "COVERED_" + fn_name, ida_name.SN_CHECK)
    fn.color = FUNC_COLOR
    # PANDA blocks may be shorter than IDA blocks
    # so use the size to color just what PANDA executed
    i = 0
    while ((pc + i) < (pc + size)):
        ida_nalt.set_item_color(pc + i, INST_COLOR)
        i = i + 1

def add_comments(info_for_pcs, selections):
    for pc, info in info_for_pcs.items():
        comment = ida_bytes.get_cmt(pc, 0)
        if (not comment):
            comment = ""
        if (selections['add_tids'] and selections['add_seqs']):
            label_portion = "(seq #, thread ID) = {}".format(sorted(list(info)))
        elif (selections['add_tids']):
            label_portion = "thread ID = {}".format(sorted(list(info)))
        else:
            label_portion = "seq # = {}".format(sorted(list(info)))
        if (comment == ""):
            comment = label_portion
        else:
            comment = comment + ", " + label_portion
        ida_bytes.set_cmt(pc, comment, 0)
        
def main():
    filename, _ = QFileDialog.getOpenFileName(None, "Open file", ".", "CSV Files(*.csv)")
    if filename == "":
        return

    processes = set()
    input_file = open(filename, "r")
    reader = csv.reader(input_file)
    
    # what mode was used to produce this output?
    fmt_row = next(reader, None)
    mode = fmt_row[0]
    # where to find the pertinent data depends upon the mode that produced it
    if ("process" == mode):
        id_index = 1
        # process ID and thread ID are in decimal
        id_radix = 10
        tid_index = 2
        pc_index = 4
        size_index = 5
        prefix = "process_"
        title = "Select Process"
        headers = ("Process Name", "PID")
        has_tid = True
    else:
        id_index = 0
        # ASID is in hex
        id_radix = 16
        tid_index = -1
        pc_index = 2
        size_index = 3
        prefix = "ASID_"
        title = "Select Address Space ID"
        headers = ("Address Space ID", "ASID")
        has_tid = False
        
    binary_name = get_root_filename()
    match_len = 0
    matched_process = None
    # skip column headers
    next(reader, None)
    for row in reader:
        processes.add((prefix + row[0], int(row[id_index], id_radix)))
        # the process names from PANDA may be truncated, so the longest one
        # that is a substring (or equal to) the binary's name is probably the
        # one we want
        if (("process" == mode) and (len(row[0]) > match_len) and binary_name.startswith(row[0])):
            match_len = len(row[0])
            matched_process = prefix + row[0]
    input_file.close()

    selections = ProcessSelectDialog.selectProcess(
        processes, matched_process, title, headers, has_tid)
    if not selections:
        return
    if not selections['selected_id']:
        return
    
    snapshot = ida_loader.snapshot_t()
    snapshot.desc = "Before coverage.py @ %s" % (datetime.datetime.now())
    ida_kernwin.take_database_snapshot(snapshot)
    
    # the next bit may take a while, if the input file is large
    ida_kernwin.show_wait_box("HIDECANCEL\nProcessing file " + filename + "...")
    
    colored_fn = False
    info_for_pcs = {}
    input_file = open(filename, "r")
    reader = csv.reader(input_file)
    # skip mode and column headers
    next(reader, None)
    next(reader, None)
    seq_num = 0
    for row in reader:
        cur_id = int(row[id_index], id_radix)
        pc = int(row[pc_index], 16)
        size = int(row[size_index])
        if (has_tid):
            cur_tid = int(row[tid_index], id_radix)
        if cur_id != selections['selected_id']:
            continue
        # get the function containing pc
        fn = idaapi.get_func(pc)
        if not fn:
            continue
        colored_fn = True
        seq_num = seq_num + 1
        color_blocks(fn, pc, size)
        if (selections['add_tids'] or selections['add_seqs']):
            if (pc not in info_for_pcs):
                info_for_pcs[pc] = set()
            # want to keep the thread IDs (if have them) with the matching
            # sequence numbers
            if (selections['add_tids'] and selections['add_seqs']):
                info_pair = "(" + str(seq_num) + ", " + str(cur_tid) + ")"
                info_for_pcs[pc].add(info_pair)
            elif (selections['add_tids']):
                info_for_pcs[pc].add(cur_tid)
            else:
                info_for_pcs[pc].add(seq_num)
    input_file.close()
    if (not colored_fn):
        print("WARNING:  did not find any selected functions")
    else:
        add_comments(info_for_pcs, selections)
    ida_kernwin.hide_wait_box()
            
if __name__ == "__main__":
    try:
        main()
    except ValueError as ve:
        msg = "Failed to read coverage CSV: %s" % (ve.message)
        QMessageBox.critical(None, "Error", msg)
    except Exception as e:
        msg = "Unexpected error: %s" % (e.message)
        QMessageBox.critical(None, "Error", msg)
