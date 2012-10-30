#!/usr/bin/env python

import IPython
import os,sys
import numpy as np
import scipy.cluster.vq as vq
from sklearn.cluster import KMeans, MiniBatchKMeans
from time import time
import logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s')

def make_features(data):
    print "Normalizing features...",
    # Set up the feature matrix
    features = np.empty(
        (data['hist'].shape[0],data['hist'].shape[1]+1),
        dtype=np.float32
    )

    features[:,:-1] = data['hist'].astype(np.float32)

    # Normalize
    for i in xrange(len(features)):
        features[i,:-1] /= features[i,:-1].sum()

    # Add another feature: how non-zero buckets
    features[:,-1] = np.array([np.count_nonzero(r) for r in features[:,:-1]])
    print "done."
    return features

print "Loading data...",
f = open(sys.argv[1])
f.seek(0)
rectype = np.dtype( [ ('caller', '<i8'), ('pc', '<i8'), ('cr3', '<i8'), ('hist', '<i4', 256) ] )
data = np.fromfile(f, dtype=rectype)
print "done (%d tap entries loaded)" % data.size

import string
ords = np.array([ord(i) for i in string.printable])

def text_ratio(hist):
    return hist[ords].sum() / float(hist.sum())

print "Creating subsets of the data..."
text = data[data['hist'].sum(axis=1) > 100]
texty_p3 = text[np.apply_along_axis(text_ratio, 1, text['hist']) > .3]
texty_p1 = text[np.apply_along_axis(text_ratio, 1, text['hist']) > .1]

p1_features = make_features(texty_p1)
p3_features = make_features(texty_p3)
uni_data = texty_p3[p3_features[:,0] == .5]
uni_features = make_features(uni_data)
print "done."

print "Feature sizes:"
print "10%%", p1_features.shape
print "30%%", p3_features.shape
print "Uni",  uni_features.shape

print "Freeing memory from original feature data...",
reduced = np.empty((data.shape[0],3))
reduced[:,0] = data['caller']
reduced[:,1] = data['pc']
reduced[:,2] = data['cr3']
del data
print "done."

print "Finding 10 means on taps with >10%% text (%d points)..." % p1_features.size,
km1 = MiniBatchKMeans(k=10, init='k-means++', n_init=1,
                     init_size=1000,
                     batch_size=1000, verbose=1)

t0 = time()
km1.fit(p1_features)
print "done in %0.3fs" % (time() - t0)

#print "Clusters:"
#for c in km.cluster_centers_:
#    print c
#print "Labels:"
#print " ".join(str(l) for l in km.labels_)

print "Finding 10 means on taps with >30%% text (%d points)..." % p3_features.size,
km3 = MiniBatchKMeans(k=10, init='k-means++', n_init=1,
                     init_size=1000,
                     batch_size=1000, verbose=1)

t0 = time()
km3.fit(p3_features)
print "done in %0.3fs" % (time() - t0)

#print "Clusters:"
#for c in km3.cluster_centers_:
#    print c
#print "Labels:"
#print " ".join(str(l) for l in km3.labels_)

print "Finding 10 means on taps with >30%% text and 50%% nulls (%d points)..." % uni_features.size,
kmu = MiniBatchKMeans(k=10, init='k-means++', n_init=1,
                     init_size=1000,
                     batch_size=1000, verbose=1)

t0 = time()
kmu.fit(uni_features)
print "done in %0.3fs" % (time() - t0)

#print "Clusters:"
#for c in km1.cluster_centers_:
#    print c
#print "Labels:"
#print " ".join(str(l) for l in km1.labels_)

IPython.embed()
