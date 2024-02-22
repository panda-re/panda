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
from PyQt5.QtWidgets import (QFileDialog, QMessageBox)

# assumes user has placed this script and ida_taint2_common.py in same folder
from ida_taint2_common import (MaxTCNSelectDialog, ProcessSelectDialog, skip_csv_header)

FUNC_COLOR = 0x90EE90
INST_COLOR = 0x55AAFF

# index in the CSV file of the PID column (first = 0)
PID_INDEX = 1
# index in the CSV file of the minimum TCN column
TCN_INDEX = 4

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

def update_db(filename, semantic_labels, selected_pid, maxtcn):
    idaapi.msg("Processing ida_taint2 output for taint labels...\n")
    snapshot = ida_loader.snapshot_t()
    snapshot.desc = "Before ida_taint2.py @ %s" % (datetime.datetime.now())
    ida_kernwin.take_database_snapshot(snapshot)

    input_file = open(filename, "r")
    reader = csv.reader(input_file)
    labels_for_pc = {}
    has_tcns = skip_csv_header(reader, False)
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
        if (has_tcns):
            cur_tcn = int(row[TCN_INDEX])
            if (cur_tcn > maxtcn):
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
    idaapi.msg("...found " + str(len(labels_for_pc)) + " tainted instructions.\n")
    
def main():
    filename, _ = QFileDialog.getOpenFileName(None, "Open file", ".",
                                              "CSV Files(*.csv)")
    if filename == "":
        return
    
    processes = set()
    maxtcn_for_pid = dict()
    input_file = open(filename, "r")
    reader = csv.reader(input_file)
    
    has_tcns = skip_csv_header(reader, True)
    for row in reader:
        processes.add((row[0], int(row[PID_INDEX])))
        if (has_tcns):
            cur_tcn = int(row[TCN_INDEX])
            if (row[PID_INDEX] not in maxtcn_for_pid):
                maxtcn_for_pid[row[PID_INDEX]] = cur_tcn
            elif (cur_tcn > maxtcn_for_pid[row[PID_INDEX]]):
                maxtcn_for_pid[row[PID_INDEX]] = cur_tcn
    input_file.close()

    selected_process = ProcessSelectDialog.selectProcess(processes, maxtcn_for_pid)
    if (None == selected_process):
        return
    
    # N.B.:  0 is a valid process ID
    selected_pid = selected_process['process_id']
    sspid = str(selected_pid)
    maxtcn = 0
    if (has_tcns and (maxtcn_for_pid[sspid] > 0)):
        maxtcn = MaxTCNSelectDialog.getMaxTCN(
               selected_process['process_name'], selected_pid,
               maxtcn_for_pid[sspid])
        if (None == maxtcn):
            return
          
    semantic_labels = read_semantic_labels(filename + ".semantic_labels")

    update_db(filename, semantic_labels, selected_pid, maxtcn)


if __name__ == "__main__":
    try:
        main()
    except ValueError as ve:
        msg = "Failed to read IDA Taint CSV: %s" % (ve)
        QMessageBox.critical(None, "Error", msg)
    except Exception as e:
        msg = "Unexpected error: %s" % (e)
        QMessageBox.critical(None, "Error", msg)
