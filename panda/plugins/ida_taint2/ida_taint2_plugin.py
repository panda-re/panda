"""
IDAPython plugin to let the user indicate tainted instructions and functions
using data collected by PANDA's ida_taint2 plugin.  These indications are
made only by changing the view of the data, not the IDA database for a binary.
"""
import csv
import ctypes

import idaapi

from PyQt5 import QtCore
from PyQt5 import QtGui
from PyQt5 import QtWidgets
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QDialog, QPushButton, QTableWidget, QHeaderView, QAbstractItemView,
        QTableWidgetItem, QCheckBox, QHBoxLayout, QVBoxLayout, QGridLayout, QFileDialog, QLabel)

import ida_funcs
import ida_kernwin
import idautils

FUNCS_WINDOW_CAPTION = "Functions window"

# an orangish shade
INST_COLOR = 0x55AAFF

# dialog to let user enable old taint info, disable current taint info, or
# change file and process from which taint information is acquired
class ReuseTaintDialog(QDialog):
    GET_NEW_FILE = 1
    GET_NEW_PROCESS = 2
    CANCEL_REQUEST = -1
    
    def __init__(self, filename, selected_process):
        super(ReuseTaintDialog, self).__init__()
        
        self.setWindowTitle("Reuse ida_taint2 Settings?")
        
        btn_ok = QPushButton("OK")
        btn_ok.clicked.connect(self.accept)
        btn_ok.setDefault(True)
        
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        
        self.lbl_file = QLabel()
        self.lbl_file.setText("File:  " + filename)
        self.lbl_process = QLabel()
        self.lbl_process.setText("Process:  " + selected_process['process_name'] +
        " (ID=" + str(selected_process['process_id']) + ")")
        
        self.chkbx_reuse_file = QCheckBox("Reuse File")
        self.chkbx_reuse_file.setChecked(True)
        
        self.chkbx_reuse_process = QCheckBox("Reuse Process")
        self.chkbx_reuse_process.setChecked(True)
        
        btns_hbox = QHBoxLayout()
        btns_hbox.addStretch(1)
        btns_hbox.addWidget(btn_ok)
        btns_hbox.addWidget(btn_cancel)
        
        info_grid = QGridLayout()
        # make first column get any extra space
        info_grid.setColumnStretch(0, 1)
        # the default Qt:Alignment (when a widget is added) is fill-whole-cell
        info_grid.addWidget(self.lbl_file, 0, 0)
        info_grid.addWidget(self.chkbx_reuse_file, 0, 1)
        info_grid.addWidget(self.lbl_process, 1, 0)
        info_grid.addWidget(self.chkbx_reuse_process, 1, 1)
        
        vbox = QVBoxLayout()
        vbox.addLayout(info_grid)
        vbox.addLayout(btns_hbox)
        
        self.setLayout(vbox)
        
    def isReuseProcess(self):
        return self.chkbx_reuse_process.isChecked()
        
    def isReuseFile(self):
        return self.chkbx_reuse_file.isChecked()
        
    @classmethod
    def askToReuse(cls, filename, selected_process):
        rd = cls(filename, selected_process)
        if QDialog.Accepted == rd.exec_():
            if (not rd.isReuseFile()):
                return ReuseTaintDialog.GET_NEW_FILE
            elif (not rd.isReuseProcess()):
                return ReuseTaintDialog.GET_NEW_PROCESS
            else:
                # silly, but really a no-op
                return ReuseTaintDialog.CANCEL_REQUEST
        else:
            return ReuseTaintDialog.CANCEL_REQUEST
            
# dialog to select a process from the list provided
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
        selectionModel = self.process_table.selectionModel()
        if not selectionModel.hasSelection():
            return None
        if len(selectionModel.selectedRows()) > 1:
            raise Exception("Supposedly impossible condition reached!")
        row = selectionModel.selectedRows()[0].row()
        return {'process_name': self.process_table.item(row, 0).data(0),
        'process_id': int(self.process_table.item(row, 1).data(0))}


    @classmethod
    def selectProcess(cls, processes):
        psd = cls(processes)
        if QDialog.Accepted == psd.exec_():
            return psd.selectedProcess()
        return None
        
# chooser window for showing tainted funcions and letting user select one for
# display in the disassembly window
class TaintedFuncsChooser(ida_kernwin.Choose):
    def __init__(self, title, taintinfo):
        ida_kernwin.Choose.__init__(
            self,
            title,
            [ ["Address", 10 | ida_kernwin.Choose.CHCOL_HEX],
              ["Name",    30 | ida_kernwin.Choose.CHCOL_PLAIN] ],
            forbidden_cb=ida_kernwin.Choose.CHOOSE_HAVE_INS | 
            ida_kernwin.Choose.CHOOSE_HAVE_DEL | 
            ida_kernwin.Choose.CHOOSE_HAVE_EDIT)
        self._taintinfo = taintinfo
        self.items = []
        # icon 41 seems to be a piece of paper with an italic f on it
        self.icon = 41
        
    # shamelessly stolen from module idc
    # get the name of the function including the ea provided
    # returns empty string if none found
    def _get_func_name(self, ea):
        name = ida_funcs.get_func_name(ea)
        if not name:
            return ""
        else:
            return name
            
    def OnInit(self):
        self.items.clear()
        if (self._taintinfo.showing_taint()):
            for x in idautils.Functions():
                if (self._taintinfo.is_func_tainted(x)):
                    self.items.append([hex(x), self._get_func_name(x), x])
        return True

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnSelectLine(self, n):
        # show this function in an IDA disassembly view
        ida_kernwin.jumpto(self.items[n][2])
        return (ida_kernwin.Choose.NOTHING_CHANGED, )

    def OnRefresh(self, n):
        self.OnInit()
        # try to preserve the cursor
        return [ida_kernwin.Choose.ALL_CHANGED] + self.adjust_last_item(n)

    def OnClose(self):
        pass

# action to show the tainted functions window
class ShowTaintedFuncs(idaapi.action_handler_t):
    # good to prefix the internal action name with plugin name to avoid conflicts
    ACTION_NAME = "ida_taint2_plugin:Show Tainted Functions"
    ACTION_LABEL = "Show Tainted Functions..."
    ACTION_TOOLTIP = "List tainted functions in separate window"
    TITLE = "Tainted functions"
    def __init__(self, taintinfo):
        idaapi.action_handler_t.__init__(self)
        self.taintinfo = taintinfo

    def activate(self, ctx):
        tfc = TaintedFuncsChooser(ShowTaintedFuncs.TITLE, self.taintinfo)
        tfc.Show()
        return 1

    def update(self, ctx):
        if ((ctx.widget_type == idaapi.BWN_FUNCS) and (self.taintinfo.showing_taint())):
            return idaapi.AST_ENABLE_FOR_WIDGET
        else:
            return idaapi.AST_DISABLE_FOR_WIDGET
        
# action to show or hide taint information
class ShowHideTaint(idaapi.action_handler_t):
    # good to prefix the internal action name with plugin name to avoid conflicts
    ACTION_NAME = "ida_taint2_plugin:Show or Hide Taint"
    SHOW_ACTION_LABEL = "Show Taint"
    SHOW_ACTION_TOOLTIP = "Visually indicate tainted instructions and functions"
    HIDE_ACTION_LABEL = "Hide Taint"
    HIDE_ACTION_TOOLTIP = "Do not visually indicate tainted instructions and functions"
    def __init__(self, taintinfo):
        idaapi.action_handler_t.__init__(self)
        self.taintinfo = taintinfo

    def activate(self, ctx):
        if (self.taintinfo.showing_taint()):
            self.taintinfo.hide_taint_info()
        else:
            self.taintinfo.show_taint_info()
        return 1

    def update(self, ctx):
        if (ctx.widget_type == idaapi.BWN_DISASM):
            return idaapi.AST_ENABLE_FOR_WIDGET
        else:
            return idaapi.AST_DISABLE_FOR_WIDGET
            
class ida_taint2_plugin_t(idaapi.plugin_t):
    # PLUGIN_PROC means to load plugin when load new database, and unload it
    # when the database is closed; this means all our settings will be wiped,
    # so don't need to explicitly do that when new DB opened
    flags = idaapi.PLUGIN_PROC
    comment = "Apply information from ida_taint2 plugin output"
    help = "The hotkey is Alt-F6"
    wanted_name = "PANDA:  IDA Taint2"
    wanted_hotkey = "Alt-F6"
    
    # commonly used strings in this class
    OPEN_CAPTION = "Open ida_taint2 output file"
    OPEN_DIRECTORY = "."
    OPEN_FILTER = "CSV Files (*.csv)"
    
    # have taint information and it is currently displayed
    def showing_taint(self):
        return self._hooks_installed
        
    # have taint information, whether or not it is currently displayed
    def have_taint_info(self):
        if (None == self._taint_file):
            return False
        else:
            return True
            
    def is_instr_tainted(self, ea):
        # is this effective address in the current list of tainted addresses?
        if (ea in self._ea_to_labels):
            return True
        else:
            return False
    
    def is_func_tainted(self, ea):
        return (ea in self._tainted_funcs)
        
    # get set of labels for tainted instruction
    # if ea is not tainted, returns empty set
    def get_instr_taint_labels(self, ea):
        if (ea in self._ea_to_labels):
            return self._ea_to_labels[ea]
        else:
            return set()
        
    def have_semantic_labels(self):
        return self._have_semantic_labels
        
    def _skip_csv_header(self, reader, show_metadata):
        # newer ida_taint2 output files have some metadata before the header
        line1 = next(reader, None)
        if (line1[0].startswith("PANDA Build Date")):
            exec_time = next(reader, None)
            if (show_metadata):
                idaapi.msg(line1[0] + ":  " + line1[1] + "\n")
                idaapi.msg(exec_time[0] + ":  " + exec_time[1] + "\n")
            next(reader, None)
        
    # read semantic label information, if it exists
    def _read_semantic_labels(self):
        semantic_labels = dict()
        self._have_semantic_labels = False
        try:
            with open(self._taint_file + ".semantic_labels") as f:
                reader = csv.reader(f)
                for row in reader:
                    semantic_labels[int(row[0])]=row[1]
        except IOError:
            pass
        except OSError:
            pass
        if (len(semantic_labels) > 0):
            self._have_semantic_labels = True
        return semantic_labels

    # if the user rebased the binary, need to adjust the list of tainted
    # functions
    def rebase_taint_info(self):
        if (not (self._taint_file == None)):
            input_file = open(self._taint_file, "r")
            reader = csv.reader(input_file)
            self._tainted_funcs.clear()
            self._skip_csv_header(reader, False)
            for row in reader:
                pid = int(row[1])
                pc = int(row[2], 16)

                if pid != self._tainted_process['process_id']:
                    continue
                fn = ida_funcs.get_func(pc)
                if not fn:
                    continue
                fn_start = fn.start_ea
                self._tainted_funcs.add(fn_start)
            input_file.close()
            ida_kernwin.refresh_chooser(ShowTaintedFuncs.TITLE)
        
    def _read_taint_info(self):
        semantic_labels = self._read_semantic_labels()
        input_file = open(self._taint_file, "r")
        reader = csv.reader(input_file)
        self._ea_to_labels.clear()
        self._tainted_funcs.clear()
        self._skip_csv_header(reader, False)
        for row in reader:
            pid = int(row[1])
            pc = int(row[2], 16)
            label = int(row[3])

            try:
                label = semantic_labels[label]
            except KeyError:
                pass

            if pid != self._tainted_process['process_id']:
                continue
            fn = ida_funcs.get_func(pc)
            if not fn:
                continue
            fn_start = fn.start_ea
            self._tainted_funcs.add(fn_start)
            if pc not in self._ea_to_labels:
                self._ea_to_labels[pc] = set()
            self._ea_to_labels[pc].add(label)
        input_file.close()
        
    # select a new process from the current file, and update the associated
    # taint information
    # returns True if did so, and False if user cancelled dialog to get new
    # process
    def _update_process(self):
        selected_process = self._get_tainted_process()
        if (None == selected_process):
            # if this is first time selecting a process from this file, have
            # to wipe the file as don't have a process for it
            if (not self._seen_file):
                self._taint_file = None
            return False
        self._ea_to_labels.clear()
        self._tainted_funcs.clear()
        self._tainted_process = selected_process
        self._read_taint_info()
        return True
            
    def hide_taint_info(self):    
        self._instr_painter.unhook()
        self._instr_hint_hook.unhook()
        self._hooks_installed = False
        idaapi.refresh_idaview_anyway()
        ida_kernwin.refresh_chooser(ShowTaintedFuncs.TITLE)
    
    def show_taint_info(self):    
        self._instr_painter.hook()
        self._instr_hint_hook.hook()
        self._hooks_installed = True
        idaapi.refresh_idaview_anyway()
        ida_kernwin.refresh_chooser(ShowTaintedFuncs.TITLE)
        
    def _get_tainted_process(self):
        processes = set()
        input_file = open(self._taint_file, "r")
        reader = csv.reader(input_file)
        self._skip_csv_header(reader, not self._seen_file)
        for row in reader:
            processes.add((row[0], int(row[1])))
        input_file.close()
        
        selected_process = ProcessSelectDialog.selectProcess(processes)
        return selected_process
        
    def init(self):
        self._instr_painter = InstrPainter(self)
        self._instr_hint_hook = InstrHintHook(self)
        self._hooks_installed = False
        self._ww_hook = WatchForWindowsHook(self)
        self._ww_hook.hook()
        self._taint_file = None
        self._tainted_process = None
        self._ea_to_labels = dict()
        self._tainted_funcs = set()
        self._have_semantic_labels = False
        self._seen_file = False
        return idaapi.PLUGIN_KEEP
            
    def term(self):
        # stop watching for window context menus to open
        self._ww_hook.unhook()
        self._ww_hook = None
        # remove the painter and hints hook
        if (self._hooks_installed):
            self._instr_painter.unhook()
            self._instr_painter = None
            self._instr_hint_hook.unhook()
            self._instr_hint_hook = None
            self._hooks_installed = False
        
    def run(self, arg):
        # this is called when select the plugin from the Edit>Plugins menu
        if (not self.have_taint_info()):
            # don't even have a file of taint information selected yet
            filename, _ = QFileDialog.getOpenFileName(None,
            self.OPEN_CAPTION, self.OPEN_DIRECTORY, self.OPEN_FILTER)
            if filename == "":
                # taint must already be disabled, so no need to re-disable
                return
            self._taint_file = filename
            if (self._update_process()):
                self.show_taint_info()
                self._seen_file = True
        elif (self.showing_taint()):
            request = ReuseTaintDialog.askToReuse(self._taint_file, self._tainted_process)
            if (ReuseTaintDialog.GET_NEW_PROCESS == request):
                if (self._update_process()):
                    idaapi.refresh_idaview_anyway()
                    ida_kernwin.refresh_chooser(ShowTaintedFuncs.TITLE)
            elif (ReuseTaintDialog.GET_NEW_FILE == request):
                filename, _ = QFileDialog.getOpenFileName(None,
                self.OPEN_CAPTION, self.OPEN_DIRECTORY, self.OPEN_FILTER)
                if filename == "":
                    # user must've changed his mind
                    return
                self._taint_file = filename
                self._seen_file = False
                if (self._update_process()):
                    self._seen_file = True
                    idaapi.refresh_idaview_anyway()
                    ida_kernwin.refresh_chooser(ShowTaintedFuncs.TITLE)
        else:
            # must have an old file and process selected, but taint disabled
            # note that _update_process wipes _tainted_process and _taint_file
            # if the user cancels the process selection, so we should not have
            # _taint_file set without _tainted_process also being set
            request = ReuseTaintDialog.askToReuse(self._taint_file, self._tainted_process)
            if (ReuseTaintDialog.GET_NEW_PROCESS == request):
                if (self._update_process()):
                    self.show_taint_info()
            elif (ReuseTaintDialog.GET_NEW_FILE == request):
                filename, _ = QFileDialog.getOpenFileName(None,
                self.OPEN_CAPTION, self.OPEN_DIRECTORY, self.OPEN_FILTER)
                if (filename == ""):
                    return
                self._taint_file = filename
                self._seen_file = False
                if (self._update_process()):
                    self.show_taint_info()
                    self._seen_file = True

# class to change background color on tainted instructions in disassembly view
class InstrPainter(idaapi.IDP_Hooks):
    def __init__(self, taintinfo):
        super(InstrPainter, self).__init__()
        self._taintinfo = taintinfo
    def ev_get_bg_color(self, pcolor, ea):
        if (not self._taintinfo.is_instr_tainted(ea)):
            # returning 0 means "not implemented"
            return 0
        # pcolor is a pointer to a color to hold the output
        # need to cast it to python type so can set it
        bgcolor = ctypes.cast(int(pcolor), ctypes.POINTER(ctypes.c_int))
        bgcolor[0] = INST_COLOR
        # returning 1 means "color set"
        return 1
        
# class to provide taint labels in hint on instruction in disassembly view
class InstrHintHook(idaapi.UI_Hooks):
    def __init__(self, taintinfo):
        idaapi.UI_Hooks.__init__(self)
        self._taintinfo = taintinfo
        
    def semantic_label_sorter(self, item):
        # semantic labels are formatted <packet number>-<byte offset>
        # we want to sort first by packet number, then by byte offset
        parts = item.split("-")
        packet_num = int(parts[0])
        offset = int(parts[1])
        return (packet_num, offset)
    
    def append_semantic_label(self, labels, first):
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
    
    def append_semantic_label_range(self, labels, first, last):
        if (len(labels) > 0):
            groupsep = ", "
            lastlf = labels.rfind("\n")
            if ((len(labels) - lastlf) > 50):
                groupsep = ",\n"
            updated_labels = labels + groupsep + str(first[0]) + ":" + str(first[1]) + "-" + str(last[1])
        else:
            updated_labels = str(first[0]) + ":" + str(first[1]) + "-" + str(last[1])
        return updated_labels
        
    def compress_sorted_semantic_labels(self, labels):
        clabels = ""
        first = None
        last = None
        for item in labels:
            itemparts = self.semantic_label_sorter(item)
            if (None == first):
                first = itemparts
            elif (None == last):
                if (first[0] == itemparts[0]):
                    if ((first[1]+1) == itemparts[1]):
                        last = itemparts
                    else:
                        clabels = self.append_semantic_label(clabels, first)
                        first = itemparts
                else:
                    clabels = self.append_semantic_label(clabels, first)
                    first = itemparts
            elif (last[0] == itemparts[0]):
                if ((last[1]+1) == itemparts[1]):
                    last = itemparts
                else:
                    clabels = self.append_semantic_label_range(clabels, first, last)
                    first = itemparts
                    last = None
            else:
                clabels = self.append_semantic_label_range(clabels, first, last)
                first = itemparts
                last = None
        if (None == last):
            clabels = self.append_semantic_label(clabels, first)
        else:
            clabels = self.append_semantic_label_range(clabels, first, last)
        return clabels
        
    def compress_sorted_standard_labels(self, labels):
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
        
    def get_custom_viewer_hint(self, view, place):
        if ((place is not None) and (idaapi.get_widget_type(view) == idaapi.BWN_DISASM)):
            curea = place.toea()
            label_set = self._taintinfo.get_instr_taint_labels(curea)
            if (len(label_set) > 0):
                # have to sort semantic labels differently than normal labels
                if (self._taintinfo.have_semantic_labels()):
                    sorted_labels = sorted(label_set, key=self.semantic_label_sorter)
                    compressed_labels = self.compress_sorted_semantic_labels(sorted_labels)
                else:
                    sorted_labels = sorted(label_set, key=int)
                    compressed_labels = self.compress_sorted_standard_labels(sorted_labels)
                hint = "taint labels = " + compressed_labels
                # in case someone wants to copy-n-paste the label list
                idaapi.msg("Hint for " + ('0x%x' %curea) + ":  " + hint + "\n")
                numlinefeeds = hint.count("\n")
                return(hint, (numlinefeeds+1))

# watch for the "Functions window" context menu, and add an item to it to show
# a window of tainted functions
# also watch for disassembly view context menu, and add an item to it to show
# or hide taint information
# also watch for RebaseProgram request, as will need to explicitly refresh the
# Tainted Functions window when it is done
class WatchForWindowsHook(idaapi.UI_Hooks):
    def __init__(self, taintinfo):
        idaapi.UI_Hooks.__init__(self)
        self.taintinfo = taintinfo
        self._cmdname = "<no command>"
        
    def finish_populating_widget_popup(self, widget, popup):
        widget_type = idaapi.get_widget_type(widget)
        if ((idaapi.BWN_FUNCS == widget_type) and self.taintinfo.showing_taint()):
            # about to show context menu for "Functions window" - as taint is
            # shown, add item to show window of tainted functions
            ida_kernwin.unregister_action(ShowTaintedFuncs.ACTION_NAME)

            # could also provide a shortcut and icon in the action_desc_t, if helpful
            if ida_kernwin.register_action(
                ida_kernwin.action_desc_t(
                    ShowTaintedFuncs.ACTION_NAME,
                    ShowTaintedFuncs.ACTION_LABEL,
                    ShowTaintedFuncs(self.taintinfo),
                    None,
                    ShowTaintedFuncs.ACTION_TOOLTIP)):
                    # if middle arg is None, this item is added permanently to the popup menu
                    # if it lists a TPopupMenu* handle, then this action is added just for this invocation
                    ida_kernwin.attach_action_to_popup(widget, popup, ShowTaintedFuncs.ACTION_NAME)
        elif ((idaapi.BWN_DISASM == widget_type) and self.taintinfo.have_taint_info()):
            # about to show context menu for a disassembly window - as taint
            # information is available, add either a Show or Hide item
            ida_kernwin.unregister_action(ShowHideTaint.ACTION_NAME)
            if (self.taintinfo.showing_taint()):
                if ida_kernwin.register_action(
                    ida_kernwin.action_desc_t(
                        ShowHideTaint.ACTION_NAME,
                        ShowHideTaint.HIDE_ACTION_LABEL,
                        ShowHideTaint(self.taintinfo),
                        None,
                        ShowHideTaint.HIDE_ACTION_TOOLTIP)):
                        ida_kernwin.attach_action_to_popup(widget, popup, ShowHideTaint.ACTION_NAME)
            else:
                if ida_kernwin.register_action(
                    ida_kernwin.action_desc_t(
                        ShowHideTaint.ACTION_NAME,
                        ShowHideTaint.SHOW_ACTION_LABEL,
                        ShowHideTaint(self.taintinfo),
                        None,
                        ShowHideTaint.SHOW_ACTION_TOOLTIP)):
                        ida_kernwin.attach_action_to_popup(widget, popup, ShowHideTaint.ACTION_NAME)
                    
    def preprocess_action(self, name):
        # remember what doing - may need to take special action in
        # postprocess_action
        self._cmdname = name
        return 0

    def postprocess_action(self):
        if (self._cmdname == "RebaseProgram"):
            # doesn't seem to be a way to tell if user Cancelled
            # request or not, so have to assume need to adjust
            self.taintinfo.rebase_taint_info()
        return 0
        
                    
def PLUGIN_ENTRY():
    return ida_taint2_plugin_t()