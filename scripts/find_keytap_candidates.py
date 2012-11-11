#!/usr/bin/env python

import IPython
import os,sys
import numpy as np

print "Loading data...",
f = open(sys.argv[1])
f.seek(0)
rectype = np.dtype( [ ('caller', '<i8'), ('pc', '<i8'), ('cr3', '<i8'), ('hist', '<i4', 256) ] )
data = np.fromfile(f, dtype=rectype)
print "done (%d tap entries loaded)" % data.size

def H(hist):
    probs = hist.astype(np.float32) / hist.sum()
    probs = probs[probs.nonzero()]
    return -(probs*np.log2(probs)).sum()

# Multiple of 48 bytes written
keytap_cands = data[data['hist'].sum(axis=1) % 48 == 0]
# Filter out those with entropy < 4. A single key usually has entropy ~5
keytap_cands = keytap_cands[np.apply_along_axis(H, 1, keytap_cands['hist']) > 4]

for rec in keytap_cands:
    print "%08x %08x %08x" % (rec['caller'], rec['pc'], rec['cr3'])
