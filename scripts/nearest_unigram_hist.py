#!/usr/bin/env python

import time
import IPython
import os,sys
import numpy as np
from struct import unpack
from collections import Counter
import scipy.spatial.distance
import logging

np.seterr(divide='ignore', invalid='ignore')

def kl_div(A,B):
    return np.nansum(np.multiply(A,np.log(A/B)))

def js_div(A,B):
    half=(A+B)/2
    return 0.5*kl_div(A,half)+0.5*kl_div(B,half)

f = open(sys.argv[1])
ulong_size = unpack("<i", f.read(4))[0]
ulong_fmt = '<u%d' % ulong_size
print >>sys.stderr, "target_ulong size: %d" % ulong_size
print >>sys.stderr, "Loading data...",
rectype = np.dtype( [ ('caller', ulong_fmt), ('pc', ulong_fmt), ('cr3', ulong_fmt), ('hist', '<I4', 256) ] )
data = np.fromfile(f, dtype=rectype)
print >>sys.stderr, "done (%d tap entries loaded)" % data.size

# Get rid of things with no very little data
data = data[np.sum(data['hist'],axis=1) > 80]

# Normalize
norm = data['hist'].astype('float32')
row_sums = norm.sum(axis=1)
norm = norm / row_sums[:, np.newaxis]

x = Counter(open(sys.argv[2]).read())
training = np.array([x[chr(i)] for i in range(256)], dtype=np.float32)
training /= training.sum()

# Super-fast since it's in C. Takes a ton of memory though.
#dists = scipy.spatial.distance.cdist([training], norm, 'euclidean')[0]
# Slower:
#st = time.time()
#dists = np.apply_along_axis(lambda x: js_div(training,x), 1, norm)
#ed = time.time()
#print >>sys.stderr, "Old: %f seconds" % (ed-st)

st = time.time()
mid = (norm + training) / 2
# D(train|mid[i])
left = np.nansum(np.log(training/mid)*training, axis=1)
# D(norm[i]|mid[i])
right = np.nansum(np.log(norm/mid)*norm, axis=1)
dists = (left + right) / 2
ed = time.time()

print >>sys.stderr, "New: %f seconds" % (ed-st)
#sys.exit(0)
sorted_dists = np.argsort(dists)

FMT = "%%0%dx" % (ulong_size*2)
for i in sorted_dists:
    row = data[i]
    print (FMT + " " + FMT + " " + FMT + " %f") % (row['caller'], row['pc'], row['cr3'], dists[i])
