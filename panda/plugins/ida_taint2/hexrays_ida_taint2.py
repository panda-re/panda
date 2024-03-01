"""
IDAPython plugin to ingest an ida_taint2 report to pseudocode windows.
The initial selections can be reused in a new pseudocode window, or the
selections can be changed.
"""
import csv
import idaapi
import ida_idaapi
import ida_kernwin
import ida_hexrays
import ida_lines


from copy import copy

from PyQt5.QtWidgets import (QDialog, QHBoxLayout, QLabel, QPushButton,
                             QVBoxLayout, QCheckBox, QFileDialog)

# assumes the ida_taint2_common.py file is placed in a plugins subfolder called
# common
from common.ida_taint2_common import (MaxTCNSelectDialog, ProcessSelectDialog,
                                      skip_csv_header)

INST_COLOR = 0x55AAFF

# index of process ID on row in ida_taint2 output file
PID_INDEX = 1

# index of taint compute number on row in ida_taint2 output file
TCN_INDEX = 4

filename = ""
selected_process = None
tainted_pcs = set()
has_tcns = False
process_tcn = None
maxtcn_displayed = None

class HIT2_ReuseDialog(QDialog):
    REUSE_SETTINGS = 1
    GET_NEW_SETTINGS = 2
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
        self.lbl_pid.setText("Process:  " + selected_process['process_name'] +
                             "(" + str(selected_process['process_id']) + ")")
        
        self.lbl_tcn = QLabel()
        if (process_tcn is None):
            self.lbl_tcn.setText(
                "No taint compute numbers are available in this file.")
        else:
            self.lbl_tcn.setText("Displaying maximum taint compute number of " +
                                 str(maxtcn_displayed) + " out of " +
                                 str(process_tcn) + ".") 
        
        self.chkbx_reuse = QCheckBox("Reuse Above Settings")
        self.chkbx_reuse.setChecked(True)
        
        hbox = QHBoxLayout()
        hbox.addStretch(1)
        hbox.addWidget(btn_ok)
        hbox.addWidget(btn_cancel)
        
        vbox = QVBoxLayout()
        vbox.addWidget(self.lbl_file)
        vbox.addWidget(self.lbl_pid)
        vbox.addWidget(self.lbl_tcn)
        vbox.addWidget(self.chkbx_reuse)
        vbox.addLayout(hbox)
        
        self.setLayout(vbox)
        
    def isReuseSettings(self):
        return self.chkbx_reuse.isChecked()
        
    @classmethod
    def askToReuse(cls):
        rd = cls()
        if (QDialog.Accepted == rd.exec_()):
            if (rd.isReuseSettings()):
                return HIT2_ReuseDialog.REUSE_SETTINGS
            else:
                return HIT2_ReuseDialog.GET_NEW_SETTINGS
        else:
            return HIT2_ReuseDialog.CANCEL_REQUEST


class hexrays_ida_taint2_t(ida_idaapi.plugin_t):
    # PLUGIN_PROC means to load plugin when load new database, and unload it
    # when the database is closed
    flags = ida_idaapi.PLUGIN_PROC
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
        anchor = ida_hexrays.ctree_anchor_t()
        for i in range(len(sv)):
            curline = copy(sv[i].line)
            while (len(curline) > 0):
                skipcode_index = ida_lines.tag_skipcode(curline)
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
                            if (address != ida_idaapi.BADADDR):
                                if (address in tainted_pcs):
                                    sv[i].bgcolor = INST_COLOR
                    curline = curline[skipcode_index:]

    def get_maxtcn(self, maxtcn_for_pid):
        global has_tcns
        global maxtcn_displayed
        global process_tcn
        global selected_process
        
        if (not has_tcns):
            process_tcn = None
            maxtcn_displayed = None
        else:
            sspid = str(selected_process['process_id'])
            new_process_tcn = maxtcn_for_pid[sspid]
            if (new_process_tcn > 0):
                new_maxtcn_displayed = MaxTCNSelectDialog.getMaxTCN(
                    selected_process['process_name'],
                    selected_process['process_id'], new_process_tcn)
                if (None == new_maxtcn_displayed):
                    # user changed mind - cancel entire selection
                    selected_process = None
                    process_tcn = None
                    maxtcn_displayed = None
                else:
                    process_tcn = new_process_tcn
                    maxtcn_displayed = new_maxtcn_displayed
            else:
                # only one TCN available for this process, 0
                process_tcn = 0
                maxtcn_displayed = 0
                
    def get_new_settings(self):
        global filename
        global has_tcns
        global selected_process
        
        # get output of ida_taint2 plugin to determine which lines get colored
        filename, _ = QFileDialog.getOpenFileName(None, "Open file", ".",
            "CSV Files (*.csv)")
        if filename == "":
            return
        ida_kernwin.msg("hexrays_ida_taint2:  file selected is " + filename + "\n")
            
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
            
        selected_process = ProcessSelectDialog.selectProcess(processes,
            maxtcn_for_pid)
        if (None == selected_process):
            return
            
        self.get_maxtcn(maxtcn_for_pid)
            
    def update_taint_info(self):
        global filename
        global has_tcns
        global maxtcn_displayed
        global selected_process
        global tainted_pcs
        
        selected_pid = selected_process['process_id']
        input_file = open(filename, "r")
        reader = csv.reader(input_file)
        tainted_pcs = set()
        # skip header
        skip_csv_header(reader, False)
        for row in reader:
            pid = int(row[PID_INDEX])
            pc = int(row[2], 16)
           
            if pid != selected_pid:
                continue
                
            if (has_tcns):
                cur_tcn = int(row[TCN_INDEX])
                if (cur_tcn > maxtcn_displayed):
                    continue
                
            if (pc not in tainted_pcs):
                tainted_pcs.add(pc)
        input_file.close()
            
    def color_pseudocode(self, widget, clear_old):
        global filename
        global selected_process
        global tainted_pcs
        
        vu = ida_hexrays.get_widget_vdui(widget)
        
        cfunc = vu.cfunc
        if cfunc is None:
            ida_kernwin.msg("hexrays_ida_taint2:  Widget has no " +
                "decompiled pseudocode!\n")
            return True
            
        if (0 == len(tainted_pcs)):
            self.get_new_settings()
            if (filename == ""):
                return        
            if (None == selected_process):
                return
                    
            self.update_taint_info()
        else:
            ida_kernwin.msg("hexrays_ida_taint2:  reusing " + filename +
                            " and process " + selected_process['process_name'] +
                            " (" + str(selected_process['process_id']) + ")\n")
        
        if (clear_old):
            self.clear_colors(cfunc)
            
        if (len(tainted_pcs) > 0):
            self.color_eas(cfunc, tainted_pcs)
            ida_kernwin.refresh_idaview_anyway()
        else:
            if (clear_old):
                ida_kernwin.refresh_idaview_anyway()
            ida_kernwin.msg("hexrays_ida_taint2:  no tainted PCs found " +
                            "for selected process\n")
            
        return 1
    
    def init(self):
        if (idaapi.init_hexrays_plugin()):
            # the plugin will terminate right away if return PLUGIN_OK instead
            return ida_idaapi.PLUGIN_KEEP
        else:
            # PLUGIN_SKIP means don't load the plugin
            return ida_idaapi.PLUGIN_SKIP

    def term(self):
        # nothing to do when plugin is unloaded
        pass
        
    def run(self, arg):
        global tainted_pcs
        # this is called when select the plugin from the Edit>Plugins menu
        curwidget = ida_kernwin.get_current_widget()
        if (ida_kernwin.BWN_PSEUDOCODE == ida_kernwin.get_widget_type(curwidget)):
            reuse = HIT2_ReuseDialog.GET_NEW_SETTINGS
            clear_old = False
            if (len(tainted_pcs) > 0):
                reuse = HIT2_ReuseDialog.askToReuse()
                if (HIT2_ReuseDialog.GET_NEW_SETTINGS == reuse):
                    tainted_pcs.clear()
                    # need to clear old colors in case changing process on the
                    # same decompiled function that colored before
                    clear_old = True
            if (HIT2_ReuseDialog.CANCEL_REQUEST != reuse):
                self.color_pseudocode(curwidget, clear_old)
        else:
            ida_kernwin.msg("Current window is not a pseudocode window\n")

def PLUGIN_ENTRY():
    return hexrays_ida_taint2_t()
