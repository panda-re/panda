"""
IDAPython code shared by multiple scripts or plugins.
"""
import idaapi
# *** get rid of above

from PyQt5 import QtCore
from PyQt5 import QtGui
from PyQt5 import QtWidgets
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QDialog, QPushButton, QTableWidget, QHeaderView,
                             QAbstractItemView, QTableWidgetItem, QHBoxLayout,
                             QVBoxLayout, QFormLayout, QSpinBox, QLabel)
            
# dialog to select a process from the list provided
class ProcessSelectDialog(QDialog):
    def __init__(self, processes, maxtcn_for_pid):
        super(ProcessSelectDialog, self).__init__()
        
        self.setWindowTitle("Select Process")
        
        btn_ok = QPushButton("OK")
        btn_ok.clicked.connect(self.accept)
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(3)
        self.process_table.setHorizontalHeaderLabels(("Process Name", "PID",
                                                      "Maximum TCN"))
        self.process_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch)
        self.process_table.setRowCount(len(processes))
        self.process_table.verticalHeader().setVisible(False)
        self.process_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.process_table.setSelectionMode(QAbstractItemView.SingleSelection)
        i = 0
        for p in processes:
            process_name_item = QTableWidgetItem(p[0])
            process_name_item.setFlags(
                process_name_item.flags() & ~(Qt.ItemIsEditable))
            self.process_table.setItem(i, 0, process_name_item)
            process_id_item = QTableWidgetItem(str(p[1]))
            process_id_item.setFlags(
                process_id_item.flags() & ~(Qt.ItemIsEditable))
            self.process_table.setItem(i, 1, process_id_item)
            spid = str(p[1])
            if (spid in maxtcn_for_pid):
                tcn = str(maxtcn_for_pid[spid])
            else:
                tcn = "(unknown)"
            process_tcn_item = QTableWidgetItem(tcn)
            process_tcn_item.setFlags(
                process_tcn_item.flags() & ~(Qt.ItemIsEditable))
            self.process_table.setItem(i, 2, process_tcn_item)
            i += 1
        # sort by process name (not stable, so pointless to sort by ID too)
        self.process_table.sortItems(0)
        
        hbox = QHBoxLayout()
        hbox.addStretch(1)
        hbox.addWidget(btn_ok)
        hbox.addWidget(btn_cancel)

        vbox = QVBoxLayout()
        vbox.addWidget(self.process_table)
        vbox.addLayout(hbox)

        self.setLayout(vbox)

    def selectedProcess(self):
        selection_model = self.process_table.selectionModel()
        if not selection_model.hasSelection():
            return None
        if len(selection_model.selectedRows()) > 1:
            raise RuntimeError("Supposedly impossible condition reached!")
        row = selection_model.selectedRows()[0].row()
        return {'process_name': self.process_table.item(row, 0).data(0),
        'process_id': int(self.process_table.item(row, 1).data(0))}


    @classmethod
    def selectProcess(cls, processes, maxtcn_for_pid):
        # processes is a set of tuples, where the first item is the process
        # name and the second is the process ID (as an int)
        # maxtcn_for_pid is a dictionary where the key is the process ID (as
        # a string) and the value is the maximum of the TCN values found
        # for that PID (as an int)
        psd = cls(processes, maxtcn_for_pid)
        if QDialog.Accepted == psd.exec_():
            return psd.selectedProcess()
        return None


# dialog to select the maximum taint compute number to display
class MaxTCNSelectDialog(QDialog):
    def __init__(self, process_name, pid, maxtcn, initial_max=None):
        super(MaxTCNSelectDialog, self).__init__()
        
        self.setWindowTitle("Select Maximum Taint Compute Number")
        
        btn_ok = QPushButton("OK")
        btn_ok.clicked.connect(self.accept)
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        
        lbl_process = QLabel()
        lbl_process.setText("The maximum TCN for process " + process_name +
                            " (" + str(pid) + ") is " + str(maxtcn) + ".")
        
        lbl_maxtcn = QLabel()
        lbl_maxtcn.setText("Maximum TCN to Display:")
        self.sb_maxtcn = QSpinBox()
        # default minimum is 0, step is 1, base is decimal, which is fine
        self.sb_maxtcn.setMaximum(maxtcn)
        if (initial_max is None):
            self.sb_maxtcn.setValue(maxtcn)
        else:
            self.sb_maxtcn.setValue(initial_max)
        
        btns_hbox = QHBoxLayout()
        btns_hbox.addStretch(1)
        btns_hbox.addWidget(btn_ok)
        btns_hbox.addWidget(btn_cancel)
        
        edit_fl = QFormLayout()
        edit_fl.addRow(lbl_maxtcn, self.sb_maxtcn)
        
        vbox = QVBoxLayout()
        vbox.addWidget(lbl_process)
        vbox.addLayout(edit_fl)
        vbox.addLayout(btns_hbox)
        
        self.setLayout(vbox)
        
    def selectedMaxTCN(self):
        return self.sb_maxtcn.value()
    
    @classmethod
    def getMaxTCN(cls, process_name, pid, maxtcn, initial_max=None):
        tcnsd = cls(process_name, pid, maxtcn, initial_max)
        if (QDialog.Accepted == tcnsd.exec_()):
            return tcnsd.selectedMaxTCN()
        return None

# utility to skip past the header in the ida_taint2 plugin output file
# reader is the csv.reader constructed for the file
# show_metadata is whether or not to show the build date, execution time
# and note about whether this file has taint compute numbers or not
# returns True if file has taint compute numbers and False otherwise
def skip_csv_header(reader, show_metadata):
    has_tcns = False
    # newer ida_taint2 output files have some metadata before the header
    line1 = next(reader, None)
    if (line1[0].startswith("PANDA Build Date")):
        exec_time = next(reader, None)
        if (show_metadata):
            idaapi.msg(line1[0] + ":  " + line1[1] + "\n")
            idaapi.msg(exec_time[0] + ":  " + exec_time[1] + "\n")
        # even newer files have a minimum TCN column
        hdrs = next(reader, None)
        if (hdrs[-1].startswith("minimum tcn")):
            has_tcns = True
        elif (show_metadata):
            idaapi.msg("Old file without minimum TCN column\n")
    elif (show_metadata):
        idaapi.msg("Old file without minimum TCN column\n")
    return has_tcns   
