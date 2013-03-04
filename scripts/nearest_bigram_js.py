#!/usr/bin/env python

import IPython
import sys
import numpy as np
import scipy.sparse as sp
from collections import Counter
import struct

MAX_BIGRAM = 2**16

f = open(sys.argv[2])
ulong_size = struct.unpack("<i", f.read(4))[0]
ulong_fmt = '<u%d' % ulong_size
FMT = "%%0%dx" % (ulong_size*2)

rec_hdr = np.dtype( [ ('caller', ulong_fmt), ('pc', ulong_fmt), ('cr3', ulong_fmt), ('nbins', '<I4') ] )
hist_entry = [ ('key', '<H'), ('value', '<u4') ]

meta = []
data = []
rows = []
cols = []

print >>sys.stderr, "Parsing file..."
i = 0
while True:
    hdr = np.fromfile(f, dtype=rec_hdr, count=1)
    if not hdr: break
    entries = np.fromfile(f, dtype=hist_entry, count=hdr['nbins'])
    # Might happen if a tap only wrote one byte. In that case there's no bigram
    if entries.size == 0: continue
    #if len(entries) < 5: continue
    #print >>sys.stderr, "Parsed entry with %d bins, file offset=%d" % (hdr['nbins'],f.tell())
    cols.extend(entries['key'])
    rows.extend([i]*len(entries))
    data.extend(entries['value'])
    meta.append(hdr)

    i += 1

f.close()

print >>sys.stderr, "Parsed", i, "tap points"

print >>sys.stderr, "Converting to nparrays..."
data = np.array(data,dtype=np.float32)
rows = np.array(rows)
cols = np.array(cols)

print >>sys.stderr, "Creating sparse matrix..."
spdata = sp.coo_matrix((data,[rows,cols]), (i, MAX_BIGRAM), dtype=np.float32)

print >>sys.stderr, "Converting to CSR format..."
spdata = spdata.tocsr()

print >>sys.stderr, "Normalizing..."
row_sums = np.array(spdata.sum(axis=1))[:,0]
row_indices, col_indices = spdata.nonzero()
spdata.data /= row_sums[row_indices]


print >>sys.stderr, "Loading training data..."
training = np.fromfile(open(sys.argv[1]),dtype=np.int).astype(np.float)
training /= training.sum()

# \sum{H(P_i)}
print >>sys.stderr, "Computing sum(H(Pi))..."
htrain = -(training[training.nonzero()]*np.log2(training[training.nonzero()])).sum()

hcopy = spdata.copy()
hcopy.data = hcopy.data*np.log2(hcopy.data)
hents = hcopy.sum(axis=1)
hents = -hents
# Delete the copy; not using it any more
del hcopy
rhs = (hents + htrain) / 2
del hents

# H(\sum{P_i})
print >>sys.stderr, "Computing H(sum(Pi))..."

# Tile the training vector into an Nx65536 (sparse) matrix
print >>sys.stderr, "Creating training matrix..."
training = sp.csr_matrix(training.astype(np.float32))
tdata = np.tile(training.data, spdata.shape[0])
tcols = np.tile(training.indices, spdata.shape[0])
trows = np.arange(spdata.shape[0],dtype=np.int32).repeat(len(training.indices))
mtraining = sp.coo_matrix((tdata,[trows,tcols]), shape=spdata.shape).tocsr()

spi = mtraining+spdata
del mtraining
spi.data /= 2
spi.data = spi.data*np.log2(spi.data)
lhs = spi.sum(axis=1)
lhs = -lhs
del spi

dists = lhs - rhs

dists = np.asarray(dists.T)[0]

sorted_dists = np.argsort(dists)

for i in sorted_dists:
    row = meta[i]
    print (FMT + " " + FMT + " " + FMT + " %f") % (row['caller'], row['pc'], row['cr3'], dists[i])
