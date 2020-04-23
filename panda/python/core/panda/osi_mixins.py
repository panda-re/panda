from .utils import progress
from .ffi_importer import ffi

class GArrayIterator():
    '''
    Iterator which will run a function on each iteration incrementing
    the second argument. Useful for GArrays with an accessor function
    that takes arguments of the GArray and list index. e.g., osi's
    get_one_module.
    '''
    def __init__(self, func, garray, garray_len):
        self.garray = garray
        self.garray_len = garray_len
        self.current_idx = 0
        self.func = func

    def __iter__(self):
        self.current_idx = 0
        return self

    def __next__(self):
        if self.current_idx >= self.garray_len:
            raise StopIteration
        # Would need to make this configurable before using MappingIter with other types
        ret = self.func(self.garray, self.current_idx)
        self.current_idx += 1
        return ret

class osi_mixins():
    def get_mappings(self, cpu):
        current = self.plugins['osi'].get_current_process(cpu)
        maps = self.plugins['osi'].get_mappings(cpu, current)
        map_len = self.garray_len(maps)
        return GArrayIterator(self.plugins['osi'].get_one_module, maps, map_len)
