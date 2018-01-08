#!/usr/bin/env python

from collections import Counter
import numpy as np
import unigram_hist
import sys

def ent(arr):
    norm = arr.astype('float32')
    row_sums = norm.sum(axis=1)
    norm = norm / row_sums[:, np.newaxis]
    ma = np.ma.log2(norm) * norm
    return -np.array(ma.sum(axis=1))

def chisq(arr):
    work = arr.astype('float')
    expect = ((1/256.)*work.sum(axis=1))[:,np.newaxis]
    work -= expect
    work *= work
    work /= expect
    return work.sum(axis=1)

reads = unigram_hist.load_hist(open(sys.argv[1]))
reads = reads[reads['hist'].sum(axis=1) > 500]
reads = reads[reads['cr3'] != 0]
writes = unigram_hist.load_hist(open(sys.argv[2]))
writes = writes[writes['hist'].sum(axis=1) > 500]
writes = writes[writes['cr3'] != 0]

## Chi squared test
print "Computing randomness of read buffers using Chi-Squared test..."
#read_chi,read_p = scipy.stats.chisquare(reads['hist'].T)
read_chi = chisq(reads['hist'])
print "Computing randomness of write buffers using Chi-Squared test..."
#write_chi,write_p = scipy.stats.chisquare(writes['hist'].T)
write_chi = chisq(writes['hist'])

# Entropy for each
print "Computing read buffer entropy..."
read_ent = ent(reads['hist'])

print "Computing write buffer entropy..."
write_ent = ent(writes['hist'])

# Now we reduce, looking for callers that have high entropy read and write
# buffers but low-randomness (high chi-square) write buffers
# Since we have parallel buffers we have to consistently apply the same
# masks to each.
mask = read_ent > 7
high_ent_reads = reads[mask]
read_chi = read_chi[mask]
mask = write_ent > 7
high_ent_writes = writes[mask]
write_chi = write_chi[mask]

print "High entropy reads: %d writes: %d" % (len(high_ent_reads),len(high_ent_writes))

# Further reduce so that they have low randomness on the write and
# high randomness on the read
mask = read_chi < 1000
read_candidates = high_ent_reads[mask]
read_chi = read_chi[mask]
mask = write_chi > 10000
write_candidates = high_ent_writes[mask]
write_chi = write_chi[mask]

# Intersect
intersection = np.intersect1d(read_candidates[['caller','cr3']], write_candidates[['caller','cr3']])
mask = np.in1d(read_candidates[['caller','cr3']],intersection)
read_final = read_candidates[mask]
read_chi = read_chi[mask]
mask = np.in1d(write_candidates[['caller','cr3']],intersection)
write_final = write_candidates[mask]
write_chi = write_chi[mask]

print "Results: reads: %d, writes: %d" % (len(read_final), len(write_final))
print "================ Writes ================"
for row in write_final:
    print "(%08x %08x %08x): %d bytes" % (row['caller'], row['pc'], row['cr3'], row['hist'].sum())
print "================ Reads  ================"
for row in read_final:
    print "(%08x %08x %08x): %d bytes" % (row['caller'], row['pc'], row['cr3'], row['hist'].sum())

wcount = Counter(tuple(row) for row in write_final[['caller','cr3']])
rcount = Counter(tuple(row) for row in read_final[['caller','cr3']])

print "Read x Write combinations by caller:"
for caller, cr3 in rcount:
    print "(%08x %08x): %d x %d combinations" % (caller, cr3, rcount[(caller,cr3)], wcount[(caller,cr3)])
    read_sizes = read_final['hist'][(read_final['caller'] == caller) & (read_final['cr3'] == cr3)].sum(axis=1)
    print "  Read sizes: ",
    print ", ".join(("%d" % x) for x in read_sizes)
    write_sizes = write_final['hist'][(write_final['caller'] == caller) & (write_final['cr3'] == cr3)].sum(axis=1)
    print "  Write sizes:",
    print ", ".join(("%d" % x) for x in write_sizes)
    print "  Read rand: ",
    print ", ".join(("%f" % x) for x in read_chi[(read_final['caller'] == caller) & (read_final['cr3'] == cr3)])
    print "  Write rand:",
    print ", ".join(("%f" % x) for x in write_chi[(write_final['caller'] == caller) & (write_final['cr3'] == cr3)])
    print "  Best input/output ratio (0 is best possible):",
    print min(np.abs(1-(xx/float(yy))) for xx in read_sizes for yy in write_sizes)
