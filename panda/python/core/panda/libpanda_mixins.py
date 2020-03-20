# Methods that directly pass data to/from libpanda with no extra logic beyond
# argument reformatting

from .ffi_importer import ffi

class libpanda_mixins():
    def set_pandalog(self, name):
        charptr = ffi.new("char[]", bytes(name, "utf-8"))
        self.libpanda.panda_start_pandalog(charptr)

    def set_os_name(self, os_name):
        os_name_new = ffi.new("char[]", bytes(os_name, "utf-8"))
        self.libpanda.panda_set_os_name(os_name_new)

    def enable_memcb(self):
        self._memcb = True
        self.libpanda.panda_enable_memcb()

    def virt_to_phys(self, env, addr):
        return self.libpanda.panda_virt_to_phys_external(env, addr)

    def enable_plugin(self, handle):
        self.libpanda.panda_enable_plugin(handle)

    def disable_plugin(self, handle):
        self.libpanda.panda_disable_plugin(handle)

    def disable_memcb(self):
        self._memcb = False
        self.libpanda.panda_disable_memcb()

    def enable_llvm(self):
        self.libpanda.panda_enable_llvm()

    def disable_llvm(self):
        self.libpanda.panda_disable_llvm()

    def enable_llvm_helpers(self):
        self.libpanda.panda_enable_llvm_helpers()

    def disable_llvm_helpers(self):
        self.libpanda.panda_disable_llvm_helpers()

    def flush_tb(self):
        return self.libpanda.panda_flush_tb()

    def enable_precise_pc(self):
        self.libpanda.panda_enable_precise_pc()

    def disable_precise_pc(self):
        self.libpanda.panda_disable_precise_pc()

    def in_kernel(self, cpustate):
        return self.libpanda.panda_in_kernel_external(cpustate)

    def g_malloc0(self, size):
        return self.libpanda.g_malloc0(size)

    def drive_get(self, blocktype, bus, unit):
        return self.libpanda.drive_get(blocktype,bus,unit)

    def sysbus_create_varargs(self, name, addr):
        return self.libpanda.sysbus_create_varargs(name,addr,ffi.NULL)

    def cpu_class_by_name(self, name, cpu_model):
        return self.libpanda.cpu_class_by_name(name, cpu_model)

    def object_class_by_name(self, name):
        return self.libpanda.object_class_by_name(name)

    def object_property_set_bool(self, obj, value, name):
        return self.libpanda.object_property_set_bool(obj,value,name,self.libpanda.error_abort)

    def object_class_get_name(self, objclass):
        return self.libpanda.object_class_get_name(objclass)

    def object_new(self, name):
        return self.libpanda.object_new(name)

    def object_property_get_bool(self, obj, name):
        return self.libpanda.object_property_get_bool(obj,name,self.libpanda.error_abort)

    def object_property_set_int(self,obj, value, name):
        return self.libpanda.object_property_set_int(obj, value, name, self.libpanda.error_abort)

    def object_property_get_int(self, obj, name):
        return self.libpanda.object_property_get_int(obj, name, self.libpanda.error_abort)

    def object_property_set_link(self, obj, val, name):
        return self.libpanda.object_property_set_link(obj,val,name,self.libpanda.error_abort)

    def object_property_get_link(self, obj, name):
        return self.libpanda.object_property_get_link(obj,name,self.libpanda.error_abort)

    def object_property_find(self, obj, name):
        return self.libpanda.object_property_find(obj,name,ffi.NULL)

    def memory_region_allocate_system_memory(self, mr, obj, name, ram_size):
        return self.libpanda.memory_region_allocate_system_memory(mr, obj, name, ram_size)

    def memory_region_add_subregion(self, mr, offset, sr):
        return self.libpanda.memory_region_add_subregion(mr,offset,sr)

    def memory_region_init_ram_from_file(self, mr, owner, name, size, share, path):
        return self.libpanda.memory_region_init_ram_from_file(mr, owner, name, size, share, path, self.libpanda.error_fatal)

    def create_internal_gic(self, vbi, irqs, gic_vers):
        return self.libpanda.create_internal_gic(vbi, irqs, gic_vers)

    def create_one_flash(self, name, flashbase, flashsize, filename, mr):
        return self.libpanda.create_one_flash(name, flashbase, flashsize, filename, mr)

    def create_external_gic(self, vbi, irqs, gic_vers, secure):
        return self.libpanda.create_external_gic(vbi, irqs, gic_vers, secure)

    def create_virtio_devices(self, vbi, pic):
        return self.libpanda.create_virtio_devices(vbi, pic)

    def arm_load_kernel(self, cpu, bootinfo):
        return self.libpanda.arm_load_kernel(cpu, bootinfo)

    def error_report(self, s):
        return self.libpanda.error_report(s)

    def get_system_memory(self):
        return self.libpanda.get_system_memory()

    def lookup_gic(self,n):
        return self.libpanda.lookup_gic(n)

    def current_sp(self, cpustate):
        return self.libpanda.panda_current_sp_external(cpustate)

    def current_pc(self, cpustate):
        return self.libpanda.panda_current_pc(cpustate)

    def current_asid(self, cpustate):
        return self.libpanda.panda_current_asid(cpustate)

    def disas2(self, code, size):
        self.libpanda.panda_disas(code, size)

    def cleanup(self):
        self.libpanda.panda_cleanup()

    def was_aborted(self):
        return self.libpanda.panda_was_aborted()

    def current_asid(self, cpustate):
        return self.libpanda.panda_current_asid(cpustate)
