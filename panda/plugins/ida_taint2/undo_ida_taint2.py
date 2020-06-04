"""
IDAPython Script to attempt undo of ida_taint2 changes.
"""

import datetime
import re

import ida_loader
import ida_kernwin
import ida_name
import ida_nalt
import ida_bytes
import ida_funcs
import ida_segment

import idautils

from PyQt5.QtWidgets import QMessageBox

UNDO_COLOR = 0xFFFFFF
label_regex = re.compile(r"(,\s)*taint labels = \[('?[0-9\-]+'?,*\s*)+\]")

def main():
    button_result = QMessageBox.warning(None, "Warning", "This script will attempt to undo ida_taint2.py changes. It is not perfect and will unpredictably change comments if you've made changes to comments since running ida_taint2.py. Do you want to continue?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
    if button_result == QMessageBox.No:
        return

    snapshot = ida_loader.snapshot_t()
    snapshot.desc = "Before undo_ida_taint2.py @ %s" % (datetime.datetime.now())
    ida_kernwin.take_database_snapshot(snapshot)

    for segea in idautils.Segments():
        for funcea in Functions(segea, ida_segment.getseg(segea).end_ea):
            function_name = ida_funcs.get_func_name(funcea)
            if function_name.startswith("TAINTED_"):
                ida_name.set_name(funcea, function_name.replace("TAINTED_", ""), ida_name.SN_NOWARN)
                ida_funcs.get_func(funcea).color = UNDO_COLOR
                for (startea, endea) in idautils.Chunks(funcea):
                    for head in idautils.Heads(startea, endea):
                        comment = ida_bytes.get_cmt(head, 0)
                        if comment != None and "taint labels" in comment:
                            ida_nalt.set_item_color(head, UNDO_COLOR)
                            ida_bytes.set_cmt(head, label_regex.sub("", comment), 0)
if __name__ == "__main__":
    main()
