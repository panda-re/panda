'''
Methods that directly pass data to/from QEMU with no extra logic beyond argument reformatting.

All QEMU function can be directly accessed by Python. These are here for convenience.

It's usally better to find a function name and look at the QEMU source for these functions.
'''

from .ffi_importer import ffi

class libqemu_mixins():
    def drive_get(self, blocktype, bus, unit):
        '''
        Gets DriveInfo struct from user specified information.

            Parameters:
                blocktype: BlockInterfaceType structure
                bus: integer bus
                unit: integer unit
            
            Return:
                DriveInfo struct
        '''
        return self.libpanda.drive_get(blocktype,bus,unit)

    def sysbus_create_varargs(self, name, addr):
        '''
        Returns DeviceState struct from user specified information
        Calls sysbus_create_varargs QEMU function.

            Parameters:
                name: python string
                addr: python integer representing hwaddr
            
            Return:
                DeviceState struct
        '''
        return self.libpanda.sysbus_create_varargs(name,addr,ffi.NULL)

    def cpu_class_by_name(self, name, cpu_model):
        '''
        Gets cpu class from name.
        Calls cpu_class_by_name QEMU function.

            Parameters:
                name: typename from python string
                cpu_model: string specified cpu model

            Returns:
                ObjectClass struct
        '''
        return self.libpanda.cpu_class_by_name(name, cpu_model)

    def object_class_by_name(self, name):
        '''
        Returns class as ObjectClass from name specified.
        Calls object_class_by_name QEMU function.

            Parameters:
                name: string defined by user
            
            Returns:
                struct as specified by name
        '''
        return self.libpanda.object_class_by_name(name)

    def object_property_set_bool(self, obj, value, name):
        '''
        Writes a bool value to a property.
        Calls object_property_set_bool QEMU function.

            Parameters:
                value: the value to be written to the property
                name: the name of the property
                errp: returns an error if this function fails

            Returns:
                None
        '''
        return self.libpanda.object_property_set_bool(obj,value,name,self.libpanda.error_abort)

    def object_class_get_name(self, objclass):
        '''
        Gets String QOM typename from object class.
        Calls object_class_get_name QEMU function.

            Parameters:
                objclass: class to obtain the QOM typename for.

            Returns: 
                String QOM typename for klass.
        '''
        return self.libpanda.object_class_get_name(objclass)

    def object_new(self, name):
        '''
        Creates a new object from typename.
        This function will initialize a new object using heap allocated memory.
        The returned object has a reference count of 1, and will be freed when
        the last reference is dropped.
        Calls object_new QEMU function.
            
            Parameters:
                name: The name of the type of the object to instantiate.
            
            Returns: 
                The newly allocated and instantiated object.
        '''
        return self.libpanda.object_new(name)

    def object_property_get_bool(self, obj, name):
        '''
        Pull boolean from object.
        Calls object_property_get_bool QEMU function.

            Parameters:
                obj: the object
                name: the name of the property
            
            Returns: 
                the value of the property, converted to a boolean, or NULL if an error occurs (including when the property value is not a bool).
        '''
        return self.libpanda.object_property_get_bool(obj,name,self.libpanda.error_abort)

    def object_property_set_int(self,obj, value, name):
        '''
        Set integer in QEMU object. Writes an integer value to a property.   
        Calls object_property_set_int QEMU function.
        
            Parameters:
                value: the value to be written to the property
                name: the name of the property
            
            Returns:
                None
        '''
        return self.libpanda.object_property_set_int(obj, value, name, self.libpanda.error_abort)

    def object_property_get_int(self, obj, name):
        '''
        Gets integer in QEMU object. Reads an integer value from this property.   
        Calls object_property_get_int QEMU function.

            Paramaters:
                obj: the object
                name: the name of the property
            
            Returns: 
                the value of the property, converted to an integer, or negative if an error occurs (including when the property value is not an integer).
        '''
        return self.libpanda.object_property_get_int(obj, name, self.libpanda.error_abort)

    def object_property_set_link(self, obj, val, name):
        '''
        Writes an object's canonical path to a property.
        Calls object_property_set_link QEMU function.

            Parameters:
                value: the value to be written to the property
                name: the name of the property
                errp: returns an error if this function fails

            Returns:
                None
        '''
        return self.libpanda.object_property_set_link(obj,val,name,self.libpanda.error_abort)

    def object_property_get_link(self, obj, name):
        '''
        Reads an object's canonical path to a property.
        Calls object_property_get_link QEMU function.
    
            Parameters:
                obj: the object
                name: the name of the property
                errp: returns an error if this function fails
            
            Returns:
                the value of the property, resolved from a path to an Object, or NULL if an error occurs (including when the property value is not a string or not a valid object path).
        '''
        return self.libpanda.object_property_get_link(obj,name,self.libpanda.error_abort)

    def object_property_find(self, obj, name):
        '''
        Look up a property for an object and return its #ObjectProperty if found.
        Calls object_property_find QEMU function.

            Parameters:
                obj: the object
                name: the name of the property
                errp: returns an error if this function fails
            
            Returns:
                struct ObjectProperty pointer
        '''
        return self.libpanda.object_property_find(obj,name,ffi.NULL)

    def memory_region_allocate_system_memory(self, mr, obj, name, ram_size):
        '''
        Allocates Memory region by user specificiation.
        Calls memory_region_allocation_system_memory QEMU function.

            Parameters:
                mr: MemoryRegion struct
                obj: Object struct
                name: string of region name
                ram_size: int of ram size
            
            Returns:
                None
        '''
        return self.libpanda.memory_region_allocate_system_memory(mr, obj, name, ram_size)

    def memory_region_add_subregion(self, mr, offset, sr):
        '''
        Calls memory_region_add_subregion from QEMU.
        memory_region_add_subregion: Add a subregion to a container.
        
        Adds a subregion at @offset.  The subregion may not overlap with other
        subregions (except for those explicitly marked as overlapping).  A region
        may only be added once as a subregion (unless removed with
        memory_region_del_subregion()); use memory_region_init_alias() if you
        want a region to be a subregion in multiple locations.
        
            Parameters:
                mr: the region to contain the new subregion; must be a container initialized with memory_region_init().
                offset: the offset relative to @mr where @subregion is added.
                subregion: the subregion to be added.
            
            Returns: 
                None
        '''
        return self.libpanda.memory_region_add_subregion(mr,offset,sr)

    def memory_region_init_ram_from_file(self, mr, owner, name, size, share, path):
        '''
        Calls memory_region_init_ram_from_file from QEMU.
        memory_region_init_ram_from_file:  Initialize RAM memory region with a mmap-ed backend.
        
            Parameters:
                mr: the #MemoryRegion to be initialized.
                owner: the object that tracks the region's reference count
                name: the name of the region.
                size: size of the region.
                share: %true if memory must be mmaped with the MAP_SHARED flag
                path: the path in which to allocate the RAM.
                errp: pointer to Error*, to store an error if it happens.
            
            Returns:
                None
        '''
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