import os
import subprocess as sp

VERBOSE = True
OUTARGS = None

def set_verbosity():
    global OUTARGS
    OUTARGS = {"stdout": (open(os.devnull, 'wb') if not VERBOSE else None), "stderr": (open(os.devnull, 'wb') if not VERBOSE else None)}

set_verbosity()


def verbose_off():
    global VERBOSE
    VERBOSE = False
    set_verbosity()

def verbose_on():
    global VERBOSE
    VERBOSE = True
    set_verbosity()

def verbose():
    global VERBOSE
    return VERBOSE

def out_args():
    global OUTARGS
    return OUTARGS


def vcheck_output(cmd_arr):
    if verbose():
        return sp.check_output(cmd_arr)
    return sp.check_output(cmd_arr, stderr=(open(os.devnull, 'wb')))

def vcheck_call(cmd_arr):
    if verbose():
        sp.check_call(cmd_arr)
    sp.check_call(cmd_arr, **OUTARGS)
