#!/usr/bin/env python

import IPython
import sys
import numpy as np
import scipy.sparse as sp
from collections import Counter
import struct

MAX_BIGRAM = 2**16

def batch_cosine_dists(A,B):
    """Compute cosine pairwise distances beween vectors A (dense) and B (sparse)"""
    if sp.issparse(A):
        A = np.array(A.todense())

    ## Compute distances
    # Dot products between each mean and observations
    dists = np.array(B*np.matrix(A.transpose()))
    
    # Compute norms of observations
    B_norms = B.copy()
    B_norms.data = B_norms.data**2
    B_norms = B_norms.sum(axis=1)
    B_norms = np.sqrt(B_norms)

    # Compute norms of A
    A_norms = np.sqrt((A**2).sum(axis=1))

    # Divide each row by the observation norms
    dists /= B_norms
    # Divide each column by the mean norms
    dists = (dists.transpose() / A_norms[:,np.newaxis]).transpose()

    # Turn into similarities
    dists = np.ones(dists.shape) - dists
 
    return dists

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
#spdata = {}
#for i in xrange(len(data)):
#    if i % 10000 == 0: print >>sys.stderr, i,"/",len(data)
#    for k,v in data[i]:
#        spdata[i,k] = v

print >>sys.stderr, "Converting to CSR format..."
spdata = spdata.tocsr()

print >>sys.stderr, "Normalizing..."
row_sums = np.array(spdata.sum(axis=1))[:,0]
row_indices, col_indices = spdata.nonzero()
spdata.data /= row_sums[row_indices]

print >>sys.stderr, "Loading training samples..."
training_files = sys.argv[2:]
training = np.array([np.fromfile(f,dtype=np.int) for f in training_files]).astype(np.float)
row_sums = training.sum(axis=1)
training /= row_sums[:,np.newaxis]

print >>sys.stderr, "Computing distances..."
dists = batch_cosine_dists(training, spdata)

for i, tf in enumerate(training_files):
    print >>sys.stderr, "Saving results for",tf
    outf = open(tf+'.near','w')
    for j in np.argsort(dists[:,i]):
        row = meta[j]
        print >>outf, (FMT + " " + FMT + " " + FMT + " %f") % (row['caller'], row['pc'], row['cr3'], dists[j,i])
    outf.close()
