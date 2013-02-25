#!/usr/bin/env python

import numpy as np
from collections import Counter
import sys
import glob

MAX_BIGRAM = 2**16
c = np.zeros(MAX_BIGRAM,dtype=np.int)

files = glob.glob(sys.argv[1])
if len(files) == 0: sys.exit(0)

for (i,fname) in enumerate(files):
    print fname
    s = open(fname).read()
    raw_data = ''.join(s[i]+s[i+1] for i in range(0,len(s)-1))
    x = np.fromstring(raw_data,dtype='>H')
    c += np.bincount(x,minlength=MAX_BIGRAM)
    
c.tofile(sys.argv[2])
