"""
IDAPython script to ingest an ida_taint2 report to pseudocode windows.
Adds two pop-up menu items to each pseudocode window.
The first menu item will allow the user to select a CSV output file from
PANDA's ida_taint2 plugin, select a process from that file, and then color
the pseudocode lines which are associated with effective addresses that are
tainted.
The second menu item allows the user to apply the same ida_taint2 and process
selected earlier to the current pseudocode window, without forcing him to
reselect them.
"""
import csv
import idaapi

from copy import copy

from PyQt5.QtCore import *
from PyQt5.QtWidgets import *

# unique action identifiers
LOAD_ACTION_NAME = "hexrays_ida_taint2:Load ida_taint2"
RELOAD_ACTION_NAME = "hexrays_ida_taint2:Reload ida_taint2"

INST_COLOR = 0x55AAFF

filename = ""
selected_pid = 0
tainted_pcs = set()

class HIT2_ReuseDialog(QDialog):
    REUSE_PROCESS = 1
    GET_NEW_PROCESS = 2
    CANCEL_REQUEST = 3
    
    def __init__(self):
        super(HIT2_ReuseDialog, self).__init__()
        
        self.setWindowTitle("Reuse ida_taint2 Settings?")
        
        btn_ok = QPushButton("OK")
        btn_ok.clicked.connect(self.accept)
        btn_ok.setDefault(True)
        
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        
        self.lbl_file = QLabel()
        self.lbl_file.setText("File:  " + filename)
        self.lbl_pid = QLabel()
        self.lbl_pid.setText("Process ID:  " + str(selected_pid))
        
        self.chkbx_reuse = QCheckBox("Reuse Process")
        self.chkbx_reuse.setChecked(True)
        
        hbox = QHBoxLayout()
        hbox.addStretch(1)
        hbox.addWidget(btn_ok)
        hbox.addWidget(btn_cancel)
        
        vbox = QVBoxLayout()
        vbox.addWidget(self.lbl_file)
        vbox.addWidget(self.lbl_pid)
        vbox.addWidget(self.chkbx_reuse)
        vbox.addLayout(hbox)
        
        self.setLayout(vbox)
        
    def isReuseProcess(self):
        return self.chkbx_reuse.isChecked()
        
    @classmethod
    def askToReuse(cls):
        rd = cls()
        if (QDialog.Accepted == rd.exec_()):
            if (rd.isReuseProcess()):
                return HIT2_ReuseDialog.REUSE_PROCESS
            else:
                return HIT2_ReuseDialog.GET_NEW_PROCESS
        else:
            return HIT2_ReuseDialog.CANCEL_REQUEST
            
class HIT2_ProcessSelectDialog(QDialog):
    def __init__(self, processes):
        super(HIT2_ProcessSelectDialog, self).__init__()
        
        self.setWindowTitle("Select Process")
        
        btn_ok = QPushButton("OK")
        btn_ok.clicked.connect(self.accept)
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(2)
        self.process_table.setHorizontalHeaderLabels(("Process Name", "PID"))
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

class hexrays_ida_taint2_t(idaapi.plugin_t):
    # PLUGIN_PROC means to load plugin when load new database, and unload it
    # when the database is closed
    flags = idaapi.PLUGIN_PROC
    comment = "Use ida_taint2 output to color tainted pseudocode lines"
    help = "Use Alt-F5 to select process to taint with"
    wanted_name = "PANDA:  Pseudocode ida_taint2"
    wanted_hotkey = "Alt-F5"
    
    def tag_addrcode(self, s):
        # the eas associated with a line of pseudocode are encoded in
        # invisible COLOR_ADDR tags in the line of text
        if ((idaapi.COLOR_ON == s[0]) and (chr(idaapi.COLOR_ADDR) == s[1])):
            return True
        else:
            return False
        
    def clear_colors(self, cfunc):
        # clear the background colors on all the pseudocode lines
        # as may be applying colors for different process
        sv = cfunc.get_pseudocode()
        for i in range(len(sv)):
            # background color of -1 means to use the default
            sv[i].bgcolor = 0xFFFFFFFF
            
    def color_eas(self, cfunc, tainted_pcs):
        # the plugins/bap/utils/hexrays.py file found at
        # https://github.com/BinaryAnalysisPlatform/bap-ida-python/ was
        # invaluable in determining how to extract the effective addresses
        # from each pseudocode line
        sv = cfunc.get_pseudocode()
        anchor = idaapi.ctree_anchor_t()
        for i in range(len(sv)):
            curline = copy(sv[i].line)
            while (len(curline) > 0):
                skipcode_index = idaapi.tag_skipcode(curline)
                if (0 == skipcode_index):
                    # no code found, go to next character
                    curline = curline[1:]
                else:
                    if (self.tag_addrcode(curline)):
                        addr_tag = int(curline[2:skipcode_index], 16)
                        anchor.value = addr_tag
                        if (anchor.is_citem_anchor() and
                            not anchor.is_blkcmt_anchor()):
                            address = cfunc.treeitems.at(addr_tag).ea
                            if (address != idaapi.BADADDR):
                                if (address in tainted_pcs):
                                    sv[i].bgcolor = INST_COLOR
                    curline = curline[skipcode_index:]
        
    def color_pseudocode(self, widget, clear_old):
        global filename
        global selected_pid
        global tainted_pcs
        
        vu = idaapi.get_widget_vdui(widget)

        cfunc = vu.cfunc
        if cfunc is None:
            idaapi.msg("hexrays_ida_taint2:  Widget has no " +
                "decompiled pseudocode!\n")
            return True
            
        if (0 == len(tainted_pcs)):        
            # get output of ida_taint2 plugin to determine which lines get
            # colored
            filename, _ = QFileDialog.getOpenFileName(None, "Open file", ".",
                "CSV Files (*.csv)")
            if filename == "":
                return
            idaapi.msg("hexrays_ida_taint2:  file selected is " +
                filename + "\n")
            
            processes = set()
            input_file = open(filename, "r")
            reader = csv.reader(input_file)
            next(reader, None)
            for row in reader:
                processes.add((row[0], int(row[1])))
            input_file.close()
            
            selected_pid = HIT2_ProcessSelectDialog.selectProcess(processes)
            # N.B.:  0 is a valid process ID
            if (None == selected_pid):
                return
            
            input_file = open(filename, "r")
            reader = csv.reader(input_file)
            tainted_pcs = set()
            # skip header
            next(reader, None)
            for row in reader:
                pid = int(row[1])
                pc = int(row[2], 16)
            
                if pid != selected_pid:
                    continue
                
                if (pc not in tainted_pcs):
                    tainted_pcs.add(pc)
            input_file.close()
        else:
            idaapi.msg("hexrays_ida_taint2:  reusing " + filename +
                " and process " + str(selected_pid) + "\n")
        
        if (clear_old):
            self.clear_colors(cfunc)
            
        if (len(tainted_pcs) > 0):
            self.color_eas(cfunc, tainted_pcs)
            idaapi.refresh_idaview_anyway()
        else:
            if (clear_old):
                idaapi.refresh_idaview_anyway()
            idaapi.msg("hexrays_ida_taint2:  no tainted PCs found " +
                "for selected process\n")
            
        return 1
    
    def init(self):
        if (idaapi.init_hexrays_plugin()):
            # the plugin will terminate right away if return PLUGIN_OK instead
            return idaapi.PLUGIN_KEEP
        else:
            # PLUGIN_SKIP means don't load the plugin
            return idaapi.PLUGIN_SKIP
            
    def term(self):
        # nothing to do when plugin is unloaded
        pass
        
    def run(self, arg):
        global tainted_pcs
        # this is called when select the plugin from the Edit>Plugins menu
        curwidget = idaapi.get_current_tform()
        if (idaapi.BWN_PSEUDOCODE == idaapi.get_widget_type(curwidget)):
            reuse = HIT2_ReuseDialog.GET_NEW_PROCESS
            clear_old = False
            if (len(tainted_pcs) > 0):
                reuse = HIT2_ReuseDialog.askToReuse()
                if (HIT2_ReuseDialog.GET_NEW_PROCESS == reuse):
                    tainted_pcs.clear()
                    # need to clear old colors in case changing process on the
                    # same decompiled function that colored before
                    clear_old = True
            if (HIT2_ReuseDialog.CANCEL_REQUEST != reuse):
                self.color_pseudocode(curwidget, clear_old)
        else:
            idaapi.msg("Current window is not a pseudocode window\n")

def PLUGIN_ENTRY():
    return hexrays_ida_taint2_t()