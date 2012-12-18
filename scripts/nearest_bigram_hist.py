#!/usr/bin/env python

import IPython
import sys
import numpy as np
import scipy.io
import scipy.sparse as sparse
from collections import Counter
import struct

MAX_BIGRAM = 2**16

f = open(sys.argv[1])
ulong_size = struct.unpack("<i", f.read(4))[0]
ulong_fmt = '<u%d' % ulong_size
FMT = "%%0%dx" % (ulong_size*2)

rec_hdr = np.dtype( [ ('caller', ulong_fmt), ('pc', ulong_fmt), ('cr3', ulong_fmt), ('nbins', '<I4') ] )
hist_entry = [ ('key', '<H'), ('value', '<u4') ]

meta = []
data = []
rows = []
cols = []

print "Parsing file..."
i = 0
while True:
    hdr = np.fromfile(f, dtype=rec_hdr, count=1)
    if not hdr: break
    entries = np.fromfile(f, dtype=hist_entry, count=hdr['nbins'])
    # Might happen if a tap only wrote one byte. In that case there's no bigram
    if entries.size == 0: continue
    #if len(entries) < 5: continue
    #print "Parsed entry with %d bins, file offset=%d" % (hdr['nbins'],f.tell())
    cols.extend(entries['key'])
    rows.extend([i]*len(entries))
    data.extend(entries['value'])
    meta.append(hdr)

    i += 1

f.close()

print "Converting to nparrays..."
data = np.array(data,dtype=np.float32)
rows = np.array(rows)
cols = np.array(cols)

print "Creating sparse matrix..."
spdata = sparse.coo_matrix((data,[rows,cols]), (i, MAX_BIGRAM), dtype=np.float32)
#spdata = {}
#for i in xrange(len(data)):
#    if i % 10000 == 0: print i,"/",len(data)
#    for k,v in data[i]:
#        spdata[i,k] = v

print "Converting to CSR format..."
spdata = spdata.tocsr()

print "Normalizing..."
row_sums = np.array(spdata.sum(axis=1))[:,0]
row_indices, col_indices = spdata.nonzero()
spdata.data /= row_sums[row_indices]

# Load training data and normalize
c = Counter()
txt = open(sys.argv[2]).read()
for i in range(len(txt)-1): c[txt[i:i+2]] += 1
training = np.array([c[chr((i & 0xFF00) >> 8) + chr(i & 0xFF)] for i in range(MAX_BIGRAM)],dtype=np.float32)
training /= training.sum()
training = sparse.csr_matrix(training)

print "Creating training data matrix..."
tdata = np.tile(training.data, spdata.shape[0])
tcols = np.tile(training.indices, spdata.shape[0])
trows = np.arange(spdata.shape[0]).repeat(len(training.indices))
mtraining = sparse.coo_matrix((tdata,[trows,tcols]), shape=spdata.shape).tocsr()

print "Computing distances..."
diff = mtraining - spdata
diff.data = np.square(diff.data)
dists = diff.sum(axis=1)
dists = np.asarray(dists.T)[0]

sorted_dists = np.argsort(dists)

for i in sorted_dists:
    row = meta[i]
    print (FMT + " " + FMT + " " + FMT + " %f") % (row['caller'], row['pc'], row['cr3'], dists[i])
