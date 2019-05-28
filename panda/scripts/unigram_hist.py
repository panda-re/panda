#!/usr/bin/env python

import time
import IPython
import os,sys
import numpy as np
from struct import unpack

def load_hist(f):
    ulong_size = unpack("<i", f.read(4))[0]
    ulong_fmt = '<u%d' % ulong_size
    stack_type_size = unpack("<i", f.read(4))[0]
    stack_type_fmt = '<u%d' % stack_type_size
    rectype = np.dtype( [ ('stackKind', stack_type_fmt), ('caller', ulong_fmt), ('pc', ulong_fmt), ('sidFirst', ulong_fmt), ('sidSecond', ulong_fmt), ('hist', '<i4', 256) ] )
    data = np.fromfile(f, dtype=rectype)
    return data
