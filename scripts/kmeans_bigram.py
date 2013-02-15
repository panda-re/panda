#!/usr/bin/env python

import IPython
import sys
import numpy as np
import scipy.io
import scipy.sparse as sp
import scipy.spatial.distance
from sklearn.feature_extraction.text import TfidfTransformer
import sklearn.utils
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
meta = np.array(meta)

print >>sys.stderr, "Creating sparse matrix..."
spdata = sp.coo_matrix((data,[rows,cols]), (i, MAX_BIGRAM), dtype=np.float32)
#spdata = {}
#for i in xrange(len(data)):
#    if i % 10000 == 0: print >>sys.stderr, i,"/",len(data)
#    for k,v in data[i]:
#        spdata[i,k] = v

print >>sys.stderr, "Converting to CSR format..."
spdata = spdata.tocsr()

#print >>sys.stderr, "Normalizing..."
#row_sums = np.array(spdata.sum(axis=1))[:,0]
#row_indices, col_indices = spdata.nonzero()
#spdata.data /= row_sums[row_indices]

print >>sys.stderr, "Transforming counts to TF-IDF..."
transformer = TfidfTransformer()
spdata = transformer.fit_transform(spdata)

num_means = int(sys.argv[2])

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

# Stolen from sklearn's k-means implementation
# Modified to use cosine distance
def k_init(X, k, n_local_trials=None):
    """Init k seeds according to k-means++

    Parameters
    -----------
    X: array or sparse matrix, shape (n_samples, n_features)
        The data to pick seeds for. To avoid memory copy, the input data
        should be double precision (dtype=np.float64).

    k: integer
        The number of seeds to choose

    n_local_trials: integer, optional
        The number of seeding trials for each center (except the first),
        of which the one reducing inertia the most is greedily chosen.
        Set to None to make the number of trials depend logarithmically
        on the number of seeds (2+log(k)); this is the default.

    Notes
    -----
    Selects initial cluster centers for k-mean clustering in a smart way
    to speed up convergence. see: Arthur, D. and Vassilvitskii, S.
    "k-means++: the advantages of careful seeding". ACM-SIAM symposium
    on Discrete algorithms. 2007

    Version ported from http://www.stanford.edu/~darthur/kMeansppTest.zip,
    which is the implementation used in the aforementioned paper.
    """
    n_samples, n_features = X.shape
    random_state = sklearn.utils.check_random_state(None)

    centers = np.empty((k, n_features))

    # Set the number of local seeding trials if none is given
    if n_local_trials is None:
        # This is what Arthur/Vassilvitskii tried, but did not report
        # specific results for other than mentioning in the conclusion
        # that it helped.
        n_local_trials = 2 + int(np.log(k))

    # Pick first center randomly
    center_id = random_state.randint(n_samples)
    if sp.issparse(X):
        centers[0] = X[center_id].toarray()
    else:
        centers[0] = X[center_id]

    # Initialize list of closest distances and calculate current potential
    closest_dist_sq = batch_cosine_dists(np.array([centers[0]]), X).transpose()**2
    current_pot = closest_dist_sq.sum()

    # Pick the remaining k-1 points
    for c in xrange(1, k):
        # Choose center candidates by sampling with probability proportional
        # to the squared distance to the closest existing center
        rand_vals = random_state.random_sample(n_local_trials) * current_pot
        candidate_ids = np.searchsorted(closest_dist_sq.cumsum(), rand_vals)

        # Compute distances to center candidates
        distance_to_candidates = batch_cosine_dists(X[candidate_ids], X).transpose()**2

        # Decide which candidate is the best
        best_candidate = None
        best_pot = None
        best_dist_sq = None
        for trial in xrange(n_local_trials):
            # Compute potential when including center candidate
            new_dist_sq = np.minimum(closest_dist_sq,
                                     distance_to_candidates[trial])
            new_pot = new_dist_sq.sum()

            # Store result if it is the best local trial so far
            if (best_candidate is None) or (new_pot < best_pot):
                best_candidate = candidate_ids[trial]
                best_pot = new_pot
                best_dist_sq = new_dist_sq

        # Permanently add best center candidate found in local tries
        if sp.issparse(X):
            centers[c] = X[best_candidate].toarray()
        else:
            centers[c] = X[best_candidate]
        current_pot = best_pot
        closest_dist_sq = best_dist_sq

    return centers

# kmeans++ initialization
print >>sys.stderr, "Choosing initial means (kmeans++)..."
means = k_init(spdata, num_means)

print >>sys.stderr, "initial_means:"
print >>sys.stderr, means

it = 0
assignments = np.zeros(spdata.shape[0])
while True:
    changed = False
    print >>sys.stderr, "Iteration", it
    it += 1

    ## Compute distances
    dists = batch_cosine_dists(means, spdata)
   
    ## Compute assignments
    new_assignments = np.argmin(dists, axis=1)
    if np.all(assignments == new_assignments):
        print >>sys.stderr, "No assignments changed, we are finished!"
        break

    # Update cluster assignments
    assignments = new_assignments

    # Update centroids
    new_means = np.zeros((num_means,spdata.shape[1]))
    for i in range(num_means):
        clust = spdata[np.arange(spdata.shape[0])[assignments == i]]
        mean = np.array(clust.sum(axis=0))
        mean /= clust.shape[1]
        new_means[i] = mean
    #print >>sys.stderr, [scipy.spatial.distance.cosine(means[i], new_means[i]) for i in range(num_means)]
    means = new_means

# Write out the assignemnts
for i in range(num_means):
    # At this point dists contains the distances to each centroid for each observation
    clust = meta[assignments == i]
    clust_dists = dists[:,i][assignments == i]
    if len(clust) == 0: continue
    for j, (caller, eip, pc, _) in enumerate(clust[:,0]):
        print "%016x %016x %016x %f %d" % (caller, eip, pc, clust_dists[j], i)
