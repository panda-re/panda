
# gets us ffi
from panda_datatypes import *


class TaintQuery:

    def __init__(self, query_result, panda_taint2):
        self.num_labels = query_result.num_labels
        self.tcn = query_result.tcn
        self.cb_mask = query_result.cb_mask
        self.qr = query_result
        self.taint2 = panda_taint2
        self.no_more = False

    def __iter__(self):
        return self

    def __next__(self):        
        if self.no_more:
            raise StopIteration
        done = ffi.new("bool *")
#        print("before calling taint2_query_result_next")
        label = self.taint2.taint2_query_result_next(self.qr, done)
#        print("after calling taint2_query_result_next")
        # this means there aren't any more labels
        # for next time
        if done:
            self.no_more = True
        return label

    # I think this should reset query result so we can 
    # iterate over labels again
    def reset(self):
        self.taint2.taint2_query_results_iter(self.qr)
        
