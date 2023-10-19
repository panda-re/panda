class CWrapper:
    C_Class = None
    def __init__(self, panda, obj):
        self.panda = panda
        self.obj = obj
    
    @classmethod
    def subclass_dict(cls):
        if not hasattr(cls, '_subclass_dict'):
            cls._subclass_dict = {p.ptr_class():p for p in cls.__subclasses__()}
        return cls._subclass_dict
    
    @classmethod
    def wrap(cls, panda, c_name, obj):
        if c_name in cls.subclass_dict():
            return cls.subclass_dict()[c_name](panda, obj)
    
    @classmethod
    def ptr_class(cls):
        return f"struct {cls.C_Class} *"
    
    def is_null(self, obj):
        return self.obj == self.panda.ffi.NULL

class StringWrapper(CWrapper):
    C_Class = "char"

    def __str__(self):
        if self.is_null(self.obj):
            return ""
        return self.panda.ffi.string(self.obj).decode("utf-8")

class QEMUPluginTb(CWrapper):
    C_Class = "qemu_plugin_tb"

    @property
    def n_insns(self):
        return self.panda.libpanda.qemu_plugin_tb_n_insns(self.obj)
    
    @property
    def vaddr(self):
        return self.panda.libpanda.qemu_plugin_tb_vaddr(self.obj)
    
    @property
    def pc(self):
        return self.panda.libpanda.qemu_plugin_tb_vaddr(self.obj)
    
    def get_insn(self, idx):
        raw_insn = self.panda.libpanda.qemu_plugin_tb_get_insn(self.obj, idx)
        if raw_insn == self.panda.ffi.NULL:
            return None
        return QEMUPluginInsn(self.panda, raw_insn)
    
    @property
    def insns(self):
        return list(self.iter_insns())
    
    def iter_insns(self):
        for i in range(self.n_insns):
            yield self.get_insn(i)

class QEMUPluginInsn(CWrapper):
    C_Class = "qemu_plugin_insn"

    @property
    def data(self):
        d = self.panda.libpanda.qemu_plugin_insn_data(self.obj)
        if self.is_null(d):
            return None
        return self.panda.ffi.cast("uint8_t*", d)
    
    @property
    def bytes(self):
        return bytes(self.data[0:self.size])
    
    @property
    def size(self):
        return self.panda.libpanda.qemu_plugin_insn_size(self.obj)
    
    @property
    def vaddr(self):
        return self.panda.libpanda.qemu_plugin_insn_vaddr(self.obj)
    
    @property
    def haddr(self):
        return self.panda.libpanda.qemu_plugin_insn_haddr(self.obj)
    
    @property
    def disas(self):
        d = self.panda.libpanda.qemu_plugin_insn_disas(self.obj)
        return StringWrapper(self.panda, d)
    
    @property
    def symbol(self):
        g = self.panda.libpanda.qemu_plugin_insn_symbol(self.obj)
        return StringWrapper(self.panda, g)
            