import os

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
