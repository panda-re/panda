#!/usr/bin/env python3
#  PANDA Snapshot Diff Tool
# 
#  Copyright (c) 2021 Brendan Dolan-Gavitt <brendandg@nyu.edu>
# 
#  Based on: Migration Stream Analyzer
#
#  Copyright (c) 2015 Alexander Graf <agraf@suse.de>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, see <http://www.gnu.org/licenses/>.

import json
import io
import os
import argparse
import collections
import pickle
import struct
import sys
import numpy as np
from pathlib import Path
from itertools import groupby, count

def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError:
        pass

class MigrationFile(object):
    def __init__(self, filename):
        self.filename = filename
        self.file = open(self.filename, "rb")

    def read64(self):
        return int.from_bytes(self.file.read(8), byteorder='big', signed=True)

    def read32(self):
        return int.from_bytes(self.file.read(4), byteorder='big', signed=True)

    def read16(self):
        return int.from_bytes(self.file.read(2), byteorder='big', signed=True)

    def read8(self):
        return int.from_bytes(self.file.read(1), byteorder='big', signed=True)

    def readstr(self, len = None):
        return self.readvar(len).decode('utf-8')

    def readvar(self, size = None):
        if size is None:
            size = self.read8()
        if size == 0:
            return ""
        value = self.file.read(size)
        if len(value) != size:
            raise Exception("Unexpected end of %s at 0x%x" % (self.filename, self.file.tell()))
        return value

    def tell(self):
        return self.file.tell()

    # The VMSD description is at the end of the file, after EOF. Look for
    # the last NULL byte, then for the beginning brace of JSON.
    def read_migration_debug_json(self):
        QEMU_VM_VMDESCRIPTION = 0x06

        # Remember the offset in the file when we started
        entrypos = self.file.tell()

        # Read the last 10MB
        self.file.seek(0, os.SEEK_END)
        endpos = self.file.tell()
        self.file.seek(max(-endpos, -10 * 1024 * 1024), os.SEEK_END)
        datapos = self.file.tell()
        data = self.file.read()
        # The full file read closed the file as well, reopen it
        self.file = open(self.filename, "rb")

        # Find the last NULL byte, then the first brace after that. This should
        # be the beginning of our JSON data.
        nulpos = data.rfind(b'\0')
        jsonpos = data.find(b'{', nulpos)

        # Check backwards from there and see whether we guessed right
        self.file.seek(datapos + jsonpos - 5, 0)
        if self.read8() != QEMU_VM_VMDESCRIPTION:
            raise Exception("No Debug Migration device found")

        jsonlen = self.read32()

        # Seek back to where we were at the beginning
        self.file.seek(entrypos, 0)

        return data[jsonpos:jsonpos + jsonlen]

    def close(self):
        self.file.close()

class RamSection(object):
    RAM_SAVE_FLAG_COMPRESS = 0x02
    RAM_SAVE_FLAG_MEM_SIZE = 0x04
    RAM_SAVE_FLAG_PAGE     = 0x08
    RAM_SAVE_FLAG_EOS      = 0x10
    RAM_SAVE_FLAG_CONTINUE = 0x20
    RAM_SAVE_FLAG_XBZRLE   = 0x40
    RAM_SAVE_FLAG_HOOK     = 0x80

    def __init__(self, file, version_id, ramargs, section_key):
        if version_id != 4:
            raise Exception("Unknown RAM version %d" % version_id)

        self.file = file
        self.section_key = section_key
        self.TARGET_PAGE_SIZE = ramargs['page_size']
        self.dump_memory = ramargs['dump_memory']
        self.write_memory = ramargs['write_memory']
        self.sizeinfo = collections.OrderedDict()
        self.data = collections.OrderedDict()
        self.data['section sizes'] = self.sizeinfo
        self.name = ''
        if self.write_memory:
            self.files = { }
        if self.dump_memory:
            self.memory = collections.OrderedDict()
            self.data['memory'] = self.memory
        self.ramsections = []

    def __repr__(self):
        return self.data.__repr__()

    def __str__(self):
        return self.data.__str__()

    def getDict(self):
        return self.data

    def flagStr(self, flags):
        flag_strs = []
        members = dir(self)
        for k in members:
            if k.startswith('RAM_SAVE_FLAG'):
                v = getattr(self, k)
                if flags & v: flag_strs.append(k)
        return flag_strs

    def read(self):
        # Read all RAM sections
        while True:
            addr = self.file.read64()
            flags = addr & (self.TARGET_PAGE_SIZE - 1)
            addr &= ~(self.TARGET_PAGE_SIZE - 1)
            secstart = self.file.tell() - 8

            if flags & self.RAM_SAVE_FLAG_MEM_SIZE:
                while True:
                    namelen = self.file.read8()
                    # We assume that no RAM chunk is big enough to ever
                    # hit the first byte of the address, so when we see
                    # a zero here we know it has to be an address, not the
                    # length of the next block.
                    if namelen == 0:
                        self.file.file.seek(-1, 1)
                        break
                    self.name = self.file.readstr(len = namelen)
                    len = self.file.read64()
                    self.sizeinfo[self.name] = '0x%016x' % len
                    if self.write_memory:
                        print(self.name)
                        mkdir_p('./' + os.path.dirname(self.name))
                        f = open('./' + self.name, "wb")
                        f.truncate(0)
                        f.truncate(len)
                        self.files[self.name] = f
                #print(f'RAM section START {addr:08x} flags={flags:04x} {"|".join(self.flagStr(flags))} file_off={secstart} size={len:04x} name={self.name}')
                if self.name == 'pc.ram': self.ramsections.append( ('START', addr, flags, secstart, self.file.tell(), len) )
                flags &= ~self.RAM_SAVE_FLAG_MEM_SIZE

            if flags & self.RAM_SAVE_FLAG_COMPRESS:
                if flags & self.RAM_SAVE_FLAG_CONTINUE:
                    flags &= ~self.RAM_SAVE_FLAG_CONTINUE
                else:
                    self.name = self.file.readstr()
                fill_char = self.file.read8()
                # The page in question is filled with fill_char now
                if self.write_memory and fill_char != 0:
                    self.files[self.name].seek(addr, os.SEEK_SET)
                    self.files[self.name].write(chr(fill_char) * self.TARGET_PAGE_SIZE)
                if self.dump_memory:
                    self.memory['%s (0x%016x)' % (self.name, addr)] = 'Filled with 0x%02x' % fill_char
                #print(f'RAM section COMPRESS {addr:08x} flags={flags:04x} {"|".join(self.flagStr(flags))} file_off={secstart} fill_char={fill_char:02x} name={self.name}')
                if self.name == 'pc.ram': self.ramsections.append( ('COMPRESS', addr, flags, secstart, self.file.tell(), fill_char) )
                flags &= ~self.RAM_SAVE_FLAG_COMPRESS
            elif flags & self.RAM_SAVE_FLAG_PAGE:
                if flags & self.RAM_SAVE_FLAG_CONTINUE:
                    flags &= ~self.RAM_SAVE_FLAG_CONTINUE
                else:
                    self.name = self.file.readstr()

                if self.write_memory or self.dump_memory:
                    data = self.file.readvar(size = self.TARGET_PAGE_SIZE)
                else: # Just skip RAM data
                    self.file.file.seek(self.TARGET_PAGE_SIZE, 1)

                if self.write_memory:
                    self.files[self.name].seek(addr, os.SEEK_SET)
                    self.files[self.name].write(data)
                if self.dump_memory:
                    hexdata = " ".join("{0:02x}".format(c) for c in data)
                    self.memory['%s (0x%016x)' % (self.name, addr)] = hexdata
                #print(f'RAM section PAGE {addr:08x} flags={flags:04x} {"|".join(self.flagStr(flags))} file_off={secstart} page_size={self.TARGET_PAGE_SIZE} name={self.name}')
                if self.name == 'pc.ram': self.ramsections.append( ('PAGE', addr, flags, secstart, self.file.tell(), 0) )
                flags &= ~self.RAM_SAVE_FLAG_PAGE
            elif flags & self.RAM_SAVE_FLAG_XBZRLE:
                raise Exception("XBZRLE RAM compression is not supported yet")
            elif flags & self.RAM_SAVE_FLAG_HOOK:
                raise Exception("RAM hooks don't make sense with files")

            # End of RAM section
            if flags & self.RAM_SAVE_FLAG_EOS:
                #print(f'RAM section END {addr:08x} flags={flags:04x} {"|".join(self.flagStr(flags))} file_off={secstart} page_size={self.TARGET_PAGE_SIZE} name={self.name}')
                # After EOS there will be 10 bytes:
                #  [QEMU_VM_SECTION_FOOTER(1)][ID(4)][QEMU_VM_SECTION_PART(1)][ID(4)]
                if self.name == 'pc.ram':
                    gap_data = self.file.file.read(10)
                    if gap_data != bytes.fromhex('7e000000040200000004'):
                        print('Warning: section gap did not have expected content - you may want to double-check that this replays correctly!', file=sys.stderr)
                        #print(f'gap_data: {gap_data.hex()}')
                        #print(f'expected: 7e000000040200000004')
                        #assert False
                    self.ramsections.append( ('EOS', addr, flags, secstart, self.file.tell(), 0) )
                    self.file.file.seek(-10, 1)
                break

            if flags != 0:
                raise Exception("Unknown RAM flags: %x" % flags)

    def __del__(self):
        if self.write_memory:
            for key in self.files:
                self.files[key].close()


class HTABSection(object):
    HASH_PTE_SIZE_64       = 16

    def __init__(self, file, version_id, device, section_key):
        if version_id != 1:
            raise Exception("Unknown HTAB version %d" % version_id)

        self.file = file
        self.section_key = section_key

    def read(self):

        header = self.file.read32()

        if (header == -1):
            # "no HPT" encoding
            return

        if (header > 0):
            # First section, just the hash shift
            return

        # Read until end marker
        while True:
            index = self.file.read32()
            n_valid = self.file.read16()
            n_invalid = self.file.read16()

            if index == 0 and n_valid == 0 and n_invalid == 0:
                break

            self.file.readvar(n_valid * self.HASH_PTE_SIZE_64)

    def getDict(self):
        return ""


class ConfigurationSection(object):
    def __init__(self, file):
        self.file = file

    def read(self):
        name_len = self.file.read32()
        name = self.file.readstr(len = name_len)

class VMSDFieldGeneric(object):
    def __init__(self, desc, file):
        self.file = file
        self.desc = desc
        self.data = ""

    def __repr__(self):
        return str(self.__str__())

    def __str__(self):
        return " ".join("{0:02x}".format(c) for c in self.data)

    def getDict(self):
        return self.__str__()

    def read(self):
        size = int(self.desc['size'])
        self.data = self.file.readvar(size)
        return self.data

class VMSDFieldInt(VMSDFieldGeneric):
    def __init__(self, desc, file):
        super(VMSDFieldInt, self).__init__(desc, file)
        self.size = int(desc['size'])
        self.format = '0x%%0%dx' % (self.size * 2)
        self.sdtype = '>i%d' % self.size
        self.udtype = '>u%d' % self.size

    def __repr__(self):
        if self.data < 0:
            return ('%s (%d)' % ((self.format % self.udata), self.data))
        else:
            return self.format % self.data

    def __str__(self):
        return self.__repr__()

    def getDict(self):
        return self.__str__()

    def read(self):
        super(VMSDFieldInt, self).read()
        self.sdata = int.from_bytes(self.data, byteorder='big', signed=True)
        self.udata = int.from_bytes(self.data, byteorder='big', signed=False)
        self.data = self.sdata
        return self.data

class VMSDFieldUInt(VMSDFieldInt):
    def __init__(self, desc, file):
        super(VMSDFieldUInt, self).__init__(desc, file)

    def read(self):
        super(VMSDFieldUInt, self).read()
        self.data = self.udata
        return self.data

class VMSDFieldIntLE(VMSDFieldInt):
    def __init__(self, desc, file):
        super(VMSDFieldIntLE, self).__init__(desc, file)
        self.dtype = '<i%d' % self.size

class VMSDFieldBool(VMSDFieldGeneric):
    def __init__(self, desc, file):
        super(VMSDFieldBool, self).__init__(desc, file)

    def __repr__(self):
        return self.data.__repr__()

    def __str__(self):
        return self.data.__str__()

    def getDict(self):
        return self.data

    def read(self):
        super(VMSDFieldBool, self).read()
        if self.data[0] == 0:
            self.data = False
        else:
            self.data = True
        return self.data

class VMSDFieldStruct(VMSDFieldGeneric):
    QEMU_VM_SUBSECTION    = 0x05

    def __init__(self, desc, file):
        super(VMSDFieldStruct, self).__init__(desc, file)
        self.data = collections.OrderedDict()

        # When we see compressed array elements, unfold them here
        new_fields = []
        for field in self.desc['struct']['fields']:
            if not 'array_len' in field:
                new_fields.append(field)
                continue
            array_len = field.pop('array_len')
            field['index'] = 0
            new_fields.append(field)
            for i in range(1, array_len):
                c = field.copy()
                c['index'] = i
                new_fields.append(c)

        self.desc['struct']['fields'] = new_fields

    def __repr__(self):
        return self.data.__repr__()

    def __str__(self):
        return self.data.__str__()

    def read(self):
        for field in self.desc['struct']['fields']:
            try:
                reader = vmsd_field_readers[field['type']]
            except:
                reader = VMSDFieldGeneric

            field['data'] = reader(field, self.file)
            field['data'].read()

            if 'index' in field:
                if field['name'] not in self.data:
                    self.data[field['name']] = []
                a = self.data[field['name']]
                if len(a) != int(field['index']):
                    raise Exception("internal index of data field unmatched (%d/%d)" % (len(a), int(field['index'])))
                a.append(field['data'])
            else:
                self.data[field['name']] = field['data']

        if 'subsections' in self.desc['struct']:
            for subsection in self.desc['struct']['subsections']:
                if self.file.read8() != self.QEMU_VM_SUBSECTION:
                    raise Exception("Subsection %s not found at offset %x" % ( subsection['vmsd_name'], self.file.tell()))
                name = self.file.readstr()
                version_id = self.file.read32()
                self.data[name] = VMSDSection(self.file, version_id, subsection, (name, 0))
                self.data[name].read()

    def getDictItem(self, value):
       # Strings would fall into the array category, treat
       # them specially
       if value.__class__ is ''.__class__:
           return value

       try:
           return self.getDictOrderedDict(value)
       except:
           try:
               return self.getDictArray(value)
           except:
               try:
                   return value.getDict()
               except:
                   return value

    def getDictArray(self, array):
        r = []
        for value in array:
           r.append(self.getDictItem(value))
        return r

    def getDictOrderedDict(self, dict):
        r = collections.OrderedDict()
        for (key, value) in dict.items():
            r[key] = self.getDictItem(value)
        return r

    def getDict(self):
        return self.getDictOrderedDict(self.data)

vmsd_field_readers = {
    "bool" : VMSDFieldBool,
    "int8" : VMSDFieldInt,
    "int16" : VMSDFieldInt,
    "int32" : VMSDFieldInt,
    "int32 equal" : VMSDFieldInt,
    "int32 le" : VMSDFieldIntLE,
    "int64" : VMSDFieldInt,
    "uint8" : VMSDFieldUInt,
    "uint16" : VMSDFieldUInt,
    "uint32" : VMSDFieldUInt,
    "uint32 equal" : VMSDFieldUInt,
    "uint64" : VMSDFieldUInt,
    "int64 equal" : VMSDFieldInt,
    "uint8 equal" : VMSDFieldInt,
    "uint16 equal" : VMSDFieldInt,
    "float64" : VMSDFieldGeneric,
    "timer" : VMSDFieldGeneric,
    "buffer" : VMSDFieldGeneric,
    "unused_buffer" : VMSDFieldGeneric,
    "bitmap" : VMSDFieldGeneric,
    "struct" : VMSDFieldStruct,
    "unknown" : VMSDFieldGeneric,
}

class VMSDSection(VMSDFieldStruct):
    def __init__(self, file, version_id, device, section_key):
        self.file = file
        self.data = ""
        self.vmsd_name = ""
        self.section_key = section_key
        desc = device
        if 'vmsd_name' in device:
            self.vmsd_name = device['vmsd_name']

        # A section really is nothing but a FieldStruct :)
        super(VMSDSection, self).__init__({ 'struct' : desc }, file)

###############################################################################

class MigrationDump(object):
    QEMU_VM_FILE_MAGIC    = 0x5145564d
    QEMU_VM_FILE_VERSION  = 0x00000003
    QEMU_VM_EOF           = 0x00
    QEMU_VM_SECTION_START = 0x01
    QEMU_VM_SECTION_PART  = 0x02
    QEMU_VM_SECTION_END   = 0x03
    QEMU_VM_SECTION_FULL  = 0x04
    QEMU_VM_SUBSECTION    = 0x05
    QEMU_VM_VMDESCRIPTION = 0x06
    QEMU_VM_CONFIGURATION = 0x07
    QEMU_VM_SECTION_FOOTER= 0x7e

    def __init__(self, filename):
        self.section_classes = { ( 'ram', 0 ) : [ RamSection, None ],
                                 ( 'spapr/htab', 0) : ( HTABSection, None ) }
        self.filename = filename
        self.vmsd_desc = None

    def read(self, desc_only = False, dump_memory = False, write_memory = False):
        # Read in the whole file
        file = MigrationFile(self.filename)

        # File magic
        data = file.read32()
        if data != self.QEMU_VM_FILE_MAGIC:
            raise Exception("Invalid file magic %x" % data)

        # Version (has to be v3)
        data = file.read32()
        if data != self.QEMU_VM_FILE_VERSION:
            raise Exception("Invalid version number %d" % data)

        self.load_vmsd_json(file)

        # Read sections
        self.sections = collections.OrderedDict()

        if desc_only:
            return

        ramargs = {}
        ramargs['page_size'] = self.vmsd_desc['page_size']
        ramargs['dump_memory'] = dump_memory
        ramargs['write_memory'] = write_memory
        self.section_classes[('ram',0)][1] = ramargs

        while True:
            section_type = file.read8()
            if section_type == self.QEMU_VM_EOF:
                #print('Section QEMU_VM_EOF')
                break
            elif section_type == self.QEMU_VM_CONFIGURATION:
                #print('Section QEMU_VM_CONFIGURATION')
                section = ConfigurationSection(file)
                section.read()
            elif section_type == self.QEMU_VM_SECTION_START or section_type == self.QEMU_VM_SECTION_FULL:
                section_id = file.read32()
                name = file.readstr()
                instance_id = file.read32()
                version_id = file.read32()
                section_key = (name, instance_id)
                classdesc = self.section_classes[section_key]
                section = classdesc[0](file, version_id, classdesc[1], section_key)
                self.sections[section_id] = section
                #print(f'Section QEMU_VM_SECTION_START/QEMU_VM_SECTION_FULL {section_id=} {name=}')
                section.read()
            elif section_type == self.QEMU_VM_SECTION_PART or section_type == self.QEMU_VM_SECTION_END:
                section_id = file.read32()
                #print(f'Section QEMU_VM_SECTION_PART/QEMU_VM_SECTION_END {section_id}')
                self.sections[section_id].read()
            elif section_type == self.QEMU_VM_SECTION_FOOTER:
                read_section_id = file.read32()
                if read_section_id != section_id:
                    raise Exception("Mismatched section footer: %x vs %x" % (read_section_id, section_id))
                #print(f'Section QEMU_VM_SECTION_FOOTER {read_section_id}')
            else:
                raise Exception("Unknown section type: %d" % section_type)
        #file.close()

    def load_vmsd_json(self, file):
        vmsd_json = file.read_migration_debug_json()
        self.vmsd_desc = json.loads(vmsd_json, object_pairs_hook=collections.OrderedDict)
        for device in self.vmsd_desc['devices']:
            key = (device['name'], device['instance_id'])
            value = ( VMSDSection, device )
            self.section_classes[key] = value

    def getDict(self):
        r = collections.OrderedDict()
        for (key, value) in self.sections.items():
           key = "%s (%d)" % ( value.section_key[0], key )
           r[key] = value.getDict()
        return r

def make_diff(file1, file2):
    dump1 = MigrationDump(file1)
    dump1.read()
    dump2 = MigrationDump(file2)
    dump2.read()

    ram1 = [r for r in dump1.sections.values() if isinstance(r, RamSection)]
    ram2 = [r for r in dump2.sections.values() if isinstance(r, RamSection)]
    assert len(ram1) == 1
    assert len(ram2) == 1
    ram1 = ram1[0]
    ram2 = ram2[0]
    addrs1 = {x[1]: x for x in ram1.ramsections if x[0] != 'EOS'}
    addrs2 = {x[1]: x for x in ram2.ramsections if x[0] != 'EOS'}

    # Sanity check: RAM sizes need to be equal
    ram_size1 = ram1.ramsections[0][-1]
    ram_size2 = ram2.ramsections[0][-1]
    if ram_size1 != ram_size2:
        print(f'Error: size of {file1} ({ram_size1:#x}) != size of {file2} ({ram_size2:#x})',file=sys.stderr)
        sys.exit(1)

    # Should be sorted but assert it
    x = ram1.ramsections
    assert all(x[i][3] <= x[i+1][3] for i in range(len(x)-1))
    x = ram2.ramsections
    assert all(x[i][3] <= x[i+1][3] for i in range(len(x)-1))

    eos_pos = [i for i in range(len(ram2.ramsections)) if ram2.ramsections[i][0] == 'EOS']

    assert addrs1.keys() == addrs2.keys()

    diffs = {}
    for a in addrs1:
        t1, _, f1, s1, e1, fc1 = addrs1[a]
        t2, _, f2, s2, e2, fc2 = addrs2[a]
        sz1 = e1 - s1
        sz2 = e2 - s2
        if t1 != t2:
            # Types are diff, no hope of similarity. Save the latter.
            #print(f'[{a:08x}] DIFF types {t1} != {t2}')
            ram2.file.file.seek(s2)
            data2 = ram2.file.file.read(sz2)
            diffs[a] = ('COPY', data2)
        elif sz1 != sz2:
            # Types are same but section sizes differ.
            #print(f'[{a:08x}] DIFF sizes {sz1} != {sz2}')
            ram2.file.file.seek(s2)
            data2 = ram2.file.file.read(sz2)
            diffs[a] = ('COPY', data2)
        else:
            # Bummer, we have to actually check
            ram1.file.file.seek(s1)
            data1 = np.fromfile(ram1.file.file, dtype=np.uint8, count=sz1)
            ram2.file.file.seek(s2)
            data2 = np.fromfile(ram2.file.file, dtype=np.uint8, count=sz2)
            section_diffs = (data1 != data2).nonzero()[0]
            if section_diffs.size > 0:
                #print(f'[{a:08x}] DIFF data ({section_diffs.size} bytes)')
                groups = groupby(section_diffs, key=lambda item, c=count():item-next(c))
                groups = [list(g) for k, g in groups]
                #print("   " + ", ".join(f"{g[0]}-{g[-1]+1}" for g in groups))
                diffdata = {g[0]: data2[g[0]:g[-1]+1].tobytes() for g in groups}
                diffs[a] = ('DIFF', diffdata)
            else:
                pass # No diff
    
    # A diff is: reference, header, EOS locations, diffs, footer
    f2 = open(file2, 'rb')
    diff_dict = {}
    diff_dict['reference'] = file1
    diff_dict['header'] = f2.read(ram2.ramsections[0][3])
    diff_dict['eos_pos'] = eos_pos
    diff_dict['diffs'] = diffs
    f2.seek(ram2.ramsections[-1][4])
    diff_dict['footer'] = f2.read()
    # Check for trailing EOS. In this case the gap data will be wrong on the last one.
    if ram2.ramsections[-1][0] == 'EOS':
        _, _, _, s, e, _ = ram2.ramsections[-1]
        f2.seek(s)
        diff_dict['eos_trail'] = f2.read(e-s)
    f2.close()
    return diff_dict

def find_ref(ref):
    if Path(ref).is_file():
        return ref
    elif 'PANDA_REFSNAPS' in os.environ:
        for candidate in os.environ['PANDA_REFSNAPS'].split(':'):
            p = Path(candidate, Path(ref).name)
            if p.is_file(): return str(p)
        print(f"Reference snapshot {ref} not found", file=sys.stderr)
        print(f"Searched: {os.environ['PANDA_REFSNAPS']}", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"Reference snapshot {ref} not found", file=sys.stderr)
        print(f"Hint: maybe you need to set PANDA_REFSNAPS ?", file=sys.stderr)
        sys.exit(1)

def rebuild(diff_dict, out_filename):
    dump1 = MigrationDump(find_ref(diff_dict['reference']))
    dump1.read()
    ram1 = [r for r in dump1.sections.values() if isinstance(r, RamSection)]
    assert len(ram1) == 1
    ram1 = ram1[0]
    addrs1 = {x[1]: x for x in ram1.ramsections if x[0] != 'EOS'}
    eos_pos = diff_dict['eos_pos']
    diffs = diff_dict['diffs']

    # Try to recombine into ram2_reconstruct
    ram2_reconstruct = [r for r in ram1.ramsections if r[0] != 'EOS']
    # Insert the EOS sections at the right places
    for r in ram1.ramsections:
        if r[0] == 'EOS':
            eos_proto = r
            break
    for i in eos_pos:
        ram2_reconstruct.insert(i, eos_proto)

    if 'eos_trail' in diff_dict:
        # Make sure this is consistent
        assert ram2_reconstruct[-1][0] == 'EOS'
        ram2_reconstruct[-1] = ('EOS_TRAIL', 0, 0, 0, 0, 0)

    outf = open(out_filename,'wb')
    outf.write(diff_dict['header'])
    for t1, a, f1, s1, e1, fc1 in ram2_reconstruct:
        if t1 == 'EOS_TRAIL':
            outf.write(diff_dict['eos_trail'])
        elif t1 == 'EOS':
            ram1.file.file.seek(s1)
            data = ram1.file.file.read(e1-s1)
            outf.write(data)
        elif a in diffs:
            kind, data = diffs[a]
            if kind == 'COPY':
                outf.write(data)
            elif kind == 'DIFF':
                ram1.file.file.seek(s1)
                patched_data = io.BytesIO(ram1.file.file.read(e1-s1))
                for a in data:
                    patched_data.seek(a)
                    patched_data.write(data[a])
                outf.write(patched_data.getvalue())
            else:
                assert False
        else:
            ram1.file.file.seek(s1)
            data = ram1.file.file.read(e1-s1)
            outf.write(data)
    outf.write(diff_dict['footer'])
    outf.close()

###############################################################################

def do_diff(args):
    if not args.output: args.output = args.files[1] + '.pdiff'
    diff_dict = make_diff(args.files[0], args.files[1])
    diff_file = open(args.output, 'wb')
    pickle.dump(diff_dict, diff_file)
    diff_file.close()

def do_inflate(args):
    if not args.output:
        o = Path(args.file)
        if o.suffix == '.pdiff':
            o = o.with_suffix('')
            args.output = o
        else:
            inflate.error("No output filename specified and can't guess (doesn't end in .pdiff)")
    else:
        args.output = Path(args.output)
    diff_dict = pickle.load(open(args.file, 'rb'))
    if args.output.exists():
        inflate.error(f'Output file {args.output} already exists! Will not overwrite.')
    rec_filename = str(args.output)
    rebuild(diff_dict, rec_filename)

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(title='commands', dest='command', required=True)
diffcmd = subparsers.add_parser('diff', help='diff two PANDA snapshots (for compression)')
diffcmd.add_argument("files", metavar='FILE', help='snapshots to diff', nargs=2)
diffcmd.add_argument("-o", "--output", help='name of output file (default: file2.pdiff)')
diffcmd.set_defaults(func=do_diff)
inflate = subparsers.add_parser('inflate', help='reconstitute a PANDA snapshot from its diff')
inflate.add_argument("file", help='pdiff file to reconstitute')
inflate.add_argument("-o", "--output", help='name of output file (default: filename with .pdiff removed)')
inflate.set_defaults(func=do_inflate)
args = parser.parse_args()
args.func(args)
