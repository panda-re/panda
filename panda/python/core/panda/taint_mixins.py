"""
Convenience methods for interacting with the taint subsystem.
"""

from .utils import progress, debug
from .ffi_importer import ffi
from .taint import TaintQuery

class taint_mixins():
    def taint_enable(self, cont=True):
        """
        Inform python that taint is enabled.
        """
        if not self.taint_enabled:
            progress("taint not enabled -- enabling")
            self.vm_stop()
            self.require("taint2")
#            self.queue_main_loop_wait_fn(self.require, ["taint2"])
            self.queue_main_loop_wait_fn(self.plugins['taint2'].taint2_enable_taint, [])
            if cont:
                self.queue_main_loop_wait_fn(self.libpanda.panda_cont, [])
            self.taint_enabled = True

    # label all bytes in this register.
    # or at least four of them
    def taint_label_reg(self, reg_num, label):
        self.taint_enable(cont=False)
        #if debug:
        #    progress("taint_reg reg=%d label=%d" % (reg_num, label))

        # XXX must ensure labeling is done in a before_block_invalidate that rets 1
        #     or some other safe way where the main_loop_wait code will always be run
        #self.stop()
        for i in range(self.register_size):
            self.queue_main_loop_wait_fn(self.plugins['taint2'].taint2_label_reg, [reg_num, i, label])
        self.queue_main_loop_wait_fn(self.libpanda.panda_cont, [])

    def taint_label_ram(self, addr, label):
        self.taint_enable(cont=False)
        #if debug:
            #progress("taint_ram addr=0x%x label=%d" % (addr, label))

        # XXX must ensure labeling is done in a before_block_invalidate that rets 1
        #     or some other safe way where the main_loop_wait code will always be run
        #self.stop()
        self.queue_main_loop_wait_fn(self.plugins['taint2'].taint2_label_ram, [addr, label])
        self.queue_main_loop_wait_fn(self.libpanda.panda_cont, [])

    # returns true if any bytes in this register have any taint labels
    def taint_check_reg(self, reg_num):
        if not self.taint_enabled: return False
#        if debug:
#            progress("taint_check_reg %d" % (reg_num))
        for offset in range(self.register_size):
            if self.plugins['taint2'].taint2_query_reg(reg_num, offset) > 0:
                return True

    # returns true if this physical address is tainted
    def taint_check_ram(self, addr):
        if not self.taint_enabled: return False
        if self.plugins['taint2'].taint2_query_ram(addr) > 0:
            return True

    # returns array of results, one for each byte in this register
    # None if no taint.  QueryResult struct otherwise
    def taint_get_reg(self, reg_num):
        if not self.taint_enabled: return None
        if debug:
            progress("taint_get_reg %d" % (reg_num)) 
        res = []
        for offset in range(self.register_size): 
            if self.plugins['taint2'].taint2_query_reg(reg_num, offset) > 0:
                query_res = ffi.new("QueryResult *")
                self.plugins['taint2'].taint2_query_reg_full(reg_num, offset, query_res)
                tq = TaintQuery(query_res, self.plugins['taint2'])
                res.append(tq)
            else:
                res.append(None)
        return res

    # returns array of results, one for each byte in this register
    # None if no taint.  QueryResult struct otherwise
    def taint_get_ram(self, addr):
        if not self.taint_enabled: return None
        if self.plugins['taint2'].taint2_query_ram(addr) > 0:
            query_res = ffi.new("QueryResult *")
            self.plugins['taint2'].taint2_query_ram_full(addr, query_res)
            tq = TaintQuery(query_res, self.plugins['taint2'])
            return tq
        else:
            return None

    # returns true if this laddr is tainted
    def taint_check_laddr(self, addr, off):
        if not self.taint_enabled: return False
        if self.plugins['taint2'].taint2_query_laddr(addr, off) > 0:
            return True

    # returns array of results, one for each byte in this laddr
    # None if no taint.  QueryResult struct otherwise
    def taint_get_laddr(self, addr, offset):
        if not self.taint_enabled: return None
        if self.plugins['taint2'].taint2_query_laddr(addr, offset) > 0:
            query_res = ffi.new("QueryResult *")
            self.plugins['taint2'].taint2_query_laddr_full(addr, offset, query_res)
            tq = TaintQuery(query_res, self.plugins['taint2'])
            return tq
        else:
            return None
