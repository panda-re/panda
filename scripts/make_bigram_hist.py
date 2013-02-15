#!/usr/bin/env python

from progressbar import ProgressBar,Percentage,Bar
import numpy as np
from collections import Counter
import sys
import glob

MAX_BIGRAM = 2**16
c = np.zeros(MAX_BIGRAM,dtype=np.int)

files = glob.glob(sys.argv[1])
if len(files) == 0: sys.exit(0)

pbar = ProgressBar(widgets=[Percentage(), Bar()], maxval=len(files)-1).start()

for (i,fname) in enumerate(files):
    s = open(fname).read()
    x = np.fromstring(''.join(sum(zip(s,s[1:]),())),dtype='>H')
    c += np.bincount(x,minlength=MAX_BIGRAM)
    pbar.update(i)
    
c.tofile(sys.argv[2])
pbar.finish()
