"""
IDAPython Script to attempt undo of ida_taint2 changes.
"""

import datetime
import re

import ida_loader
import ida_kernwin

from PyQt5.QtWidgets import *

UNDO_COLOR = 0xFFFFFF
label_regex = re.compile(r"(,\s)*taint labels = \[([0-9]+,*\s*)+\]")

def main():
    button_result = QMessageBox.warning(None, "Warning", "This script will attempt to undo ida_taint2.py changes. It is not perfect and will unpredictably change comments if you've made changes to comments since running ida_taint2.py. Do you want to continue?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
    if button_result == QMessageBox.No:
        return

    snapshot = ida_loader.snapshot_t()
    snapshot.desc = "Before undo_ida_taint2.py @ %s" % (datetime.datetime.now())
    ida_kernwin.take_database_snapshot(snapshot)

    for segea in Segments():
        for funcea in Functions(segea, SegEnd(segea)):
            function_name = GetFunctionName(funcea)
            if function_name.startswith("TAINTED_"):
                MakeName(funcea, function_name.replace("TAINTED_", ""))
                SetColor(funcea, CIC_FUNC, UNDO_COLOR)
                for (startea, endea) in Chunks(funcea):
                    for head in Heads(startea, endea):
                        comment = str(Comment(head))
                        print(comment)
                        if "taint labels" in comment:
                            SetColor(head, CIC_ITEM, UNDO_COLOR)
                            MakeComm(head, label_regex.sub("", comment))
if __name__ == "__main__":
    main()
