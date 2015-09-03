#!/usr/bin/env python

from construct import *

class SnapshotParseError(Exception):
    pass

PAGE_SIZE = 4096

def sizeof_fmt(num, suffix='B'):
    for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
        if abs(num) < 1024.0:
            return "%3.1f %s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)

# Bit of a hack: we want to repeat until
# the accumulated size of the sections equals
# the total RAM size. But constructs don't keep
# state. So we have an external function that keeps
# track of its state for us, and resets the state
# once the condition is true (so that we don't get
# odd results if we try to call it twice)
size_exceeded_total = 0
def size_exceeded(obj, ctx):
    global size_exceeded_total
    size_exceeded_total += obj.Size
    if size_exceeded_total >= ctx.Addr.Address:
        size_exceeded_total = 0
        return True
    else:
        return False

MemSizeData = RepeatUntil(size_exceeded,
        Struct("MemSizeData",
            PascalString("Name"),
            UBInt64("Size")
        )
)

class PageSizeAdapter(Adapter):
    def _encode(self, obj, ctx): return obj >> 12
    def _decode(self, obj, ctx): return obj << 12

RAMSection = Struct("RAMSection",
        BitStruct("Addr",
            PageSizeAdapter(BitField("Address", 52)),
            FlagsEnum(BitField("Flags", 12),
                RAM_SAVE_FLAG_FULL     = 0x01, # Obsolete, not used anymore
                RAM_SAVE_FLAG_COMPRESS = 0x02,
                RAM_SAVE_FLAG_MEM_SIZE = 0x04,
                RAM_SAVE_FLAG_PAGE     = 0x08,
                RAM_SAVE_FLAG_EOS      = 0x10,
                RAM_SAVE_FLAG_CONTINUE = 0x20,
            )
        ),
        If(lambda ctx: ctx.Addr.Flags.RAM_SAVE_FLAG_MEM_SIZE,
            MemSizeData
        ),
        If(lambda ctx: (ctx.Addr.Flags.RAM_SAVE_FLAG_PAGE or ctx.Addr.Flags.RAM_SAVE_FLAG_COMPRESS) and not ctx.Addr.Flags.RAM_SAVE_FLAG_CONTINUE,
            PascalString("Name")
        ),
        If(lambda ctx: ctx.Addr.Flags.RAM_SAVE_FLAG_PAGE,
            OnDemand(HexDumpAdapter(Bytes("Data", PAGE_SIZE)))
        ),
        If(lambda ctx: ctx.Addr.Flags.RAM_SAVE_FLAG_COMPRESS,
            Byte("FillByte")
        )
)

RAMBlocks = RepeatUntil(lambda obj, ctx: obj.Addr.Flags.RAM_SAVE_FLAG_EOS, RAMSection)

SaveVMHeader = Struct("SaveVMHeader", 
        Magic("QEVM"),
        UBInt32("FileVersion"),
)

SaveVMSectionStart = Struct("SaveVMSectionStart",
        UBInt32("SectionId"),
        PascalString("SectionIdString"),
        UBInt32("InstanceId"),
        UBInt32("VersionId"),
        UBInt64("SectionLength"),
        OnDemand(HexDumpAdapter(Bytes("SectionData", lambda ctx: ctx.SectionLength))),
)

SaveVMSectionFull = Struct("SaveVMSectionFull",
        UBInt32("SectionId"),
        PascalString("SectionIdString"),
        UBInt32("InstanceId"),
        UBInt32("VersionId"),
        UBInt64("SectionLength"),
        OnDemand(HexDumpAdapter(Bytes("SectionData", lambda ctx: ctx.SectionLength))),
)

SaveVMSectionPart = Struct("SaveVMSectionPart",
        UBInt32("SectionId"),
        UBInt64("SectionLength"),
        OnDemand(HexDumpAdapter(Bytes("SectionData", lambda ctx: ctx.SectionLength))),
)

SaveVMSectionEnd = Struct("SaveVMSectionEnd",
    UBInt32("SectionId"),
    UBInt64("SectionLength"),
    OnDemand(HexDumpAdapter(Bytes("SectionData", lambda ctx: ctx.SectionLength))),
)

SectionType = Enum(Byte("SectionType"),
    QEMU_VM_EOF                = 0x00,
    QEMU_VM_SECTION_START      = 0x01,
    QEMU_VM_SECTION_PART       = 0x02,
    QEMU_VM_SECTION_END        = 0x03,
    QEMU_VM_SECTION_FULL       = 0x04,
    QEMU_VM_SUBSECTION         = 0x05,
)

SaveVMSectionV4 = Struct("SaveVMSection",
        SectionType,
        Embed(Switch("Section", lambda ctx: ctx.SectionType, {
                'QEMU_VM_SECTION_START': SaveVMSectionStart,
                'QEMU_VM_SECTION_PART': SaveVMSectionPart,
                'QEMU_VM_SECTION_END': SaveVMSectionEnd,
                'QEMU_VM_SECTION_FULL': SaveVMSectionFull,
            }, default = Pass,
        )),
)

# V3 (non-PANDA) files are annoying
# Each section is parsed by whatever part of QEMU
# originally wrote it out, so there's no common format,
# and more importantly, there's no way of telling how long
# it should be. So we follow the lead of lqs2mem and just
# try to parse an empty "block" section and then the RAM
# section (which we pretend is the rest of the file)

class ByteListAdapter(Adapter):
    def _encode(self, obj, ctx): return [ ord(c) for c in obj ]
    def _decode(self, obj, ctx): return ''.join(chr(c) for c in obj)

SaveVMSectionStartV3 = Struct("SaveVMSectionStart",
        UBInt32("SectionId"),
        PascalString("SectionIdString"),
        UBInt32("InstanceId"),
        UBInt32("VersionId"),
)

SaveVMSectionV3 = Struct("SaveVMSection",
    SectionType,
    Embed(Switch("Section", lambda ctx: ctx.SectionType, {
        'QEMU_VM_SECTION_START': SaveVMSectionStartV3,
        },
        default = NotImplemented
    )),
    Switch("Data", lambda ctx: ctx.SectionIdString, {
        'block': Const(UBInt64("BlockMigrationFlags"), 0x02),
        'ram': RAMBlocks,
        },
        default = NotImplemented
    ),
)

SaveVMFile = Struct("SaveVMFile",
        SaveVMHeader,
        IfThenElse("Sections", lambda ctx: ctx.SaveVMHeader.FileVersion == 4,
            GreedyRange(SaveVMSectionV4),
            RepeatUntil(lambda obj, ctx: obj.SectionIdString == 'ram', SaveVMSectionV3),
        )
)

def print_ram_sections(ramdata, indent=''):
    for block in ramdata:
        if block.MemSizeData:
            for sect in block.MemSizeData:
                print indent + "%-32s size = %-10s (%d bytes)" % (sect.Name, sizeof_fmt(sect.Size), sect.Size)
            break

def save_ram_section(ramdata, args):
    saving = False
    for block in ramdata:
        if block.MemSizeData: continue
        if block.Name:
            if block.Name == args.write:
                saving = True
            else:
                saving = False
        if saving:
            addr = block.Addr.Address
            # Adjust for PCI hole
            if addr >= 0xe0000000:
                addr += 0x20000000;

            if block.FillByte is not None:
                data = chr(block.FillByte) * PAGE_SIZE
            elif block.Data is not None:
                data = block.Data.value
            else:
                raise SnapshotParseError("RAM block no data!")

            if args.verbose:
                print "Offset %08x writing %d bytes of data." % (addr, PAGE_SIZE)

            args.output.seek(addr)
            args.output.write(data)

if __name__ == "__main__":
    import sys
    import argparse
    parser = argparse.ArgumentParser(description='Get information from QEMU/PANDA snapshots')
    parser.add_argument('snapshot', type=argparse.FileType('r'),
            help = 'QEMU/PANDA snapshot file')
    parser.add_argument('output', nargs='?', type=argparse.FileType('w'),
            help = 'Output file (for use with -w)')
    parser.add_argument('-v', '--verbose', action='store_true', default = False,
            help = "Print out more information")
    parser.add_argument('-x', '--hexdump', action='store_true', default = False,
            help = "Print hexdump of each section as it's encountered")
    parser.add_argument('-w', '--write', action='store', metavar='SECTION', default=None,
            help = "Save SECTION to disk (you must specify an output file for this to work)")
    args = parser.parse_args()

    if args.write and not args.output:
        parser.error("if you use -w you must also give an output file")

    snpdata = SaveVMFile.parse_stream(args.snapshot)
    section_names = {}

    if snpdata.SaveVMHeader.FileVersion == 3:
        for s in snpdata.Sections:
            section_names[s.SectionId] = s.SectionIdString
            if s.SectionIdString == "ram":
                ramdata = s.Data
                print_ram_sections(ramdata)
                break
    elif snpdata.SaveVMHeader.FileVersion == 4:
        for s in snpdata.Sections:
            if s.SectionType == 'QEMU_VM_EOF': break
            name = getattr(s, 'SectionIdString', None)
            if name:
                section_names[s.SectionId] = name
            else:
                name = section_names[s.SectionId]
            section_kind = {
                'QEMU_VM_SECTION_START': 'start',
                'QEMU_VM_SECTION_PART': 'part',
                'QEMU_VM_SECTION_FULL': 'full',
                'QEMU_VM_SECTION_END': 'end',
            }[s.SectionType]
            print "%-32s (%s) size = %-10s (%d bytes)" % (name, section_kind, sizeof_fmt(s.SectionLength), s.SectionLength)
            if name == 'ram':
                ramdata = RAMBlocks.parse(s.SectionData.value)
                print_ram_sections(ramdata, indent='    ')
            else:
                if args.hexdump:
                    print s.SectionData.value
                    print
    
    if args.write:
        for s in snpdata.Sections:
            if s.SectionType == 'QEMU_VM_EOF': break
            name = section_names[s.SectionId]
            if name == args.write:
                if args.verbose:
                    print "Writing %d bytes of data from section '%s'." % (s.SectionLength, name)
                args.output.write(s.SectionData.value)
            elif name == 'ram':
                if snpdata.SaveVMHeader.FileVersion == 3:
                    ramdata = s.Data
                elif snpdata.SaveVMHeader.FileVersion == 4:
                    ramdata = RAMBlocks.parse(s.SectionData.value)
                save_ram_section(ramdata, args)
        args.output.close()
    args.snapshot.close()
