#!/usr/bin/env python

from construct import *

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
            OnDemand(Bytes("Data", 4096))
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
        OnDemand(Bytes("SectionData", lambda ctx: ctx.SectionLength)),
)

SaveVMSectionFull = Struct("SaveVMSectionFull",
        UBInt32("SectionId"),
        PascalString("SectionIdString"),
        UBInt32("InstanceId"),
        UBInt32("VersionId"),
        UBInt64("SectionLength"),
        OnDemand(Bytes("SectionData", lambda ctx: ctx.SectionLength)),
)

SaveVMSectionPart = Struct("SaveVMSectionPart",
        UBInt32("SectionId"),
        UBInt64("SectionLength"),
        OnDemand(Bytes("SectionData", lambda ctx: ctx.SectionLength)),
)

SaveVMSectionEnd = Struct("SaveVMSectionEnd",
    UBInt32("SectionId"),
    UBInt64("SectionLength"),
    OnDemand(Bytes("SectionData", lambda ctx: ctx.SectionLength)),
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

if __name__ == "__main__":
    import sys
    snpdata = SaveVMFile.parse_stream(open(sys.argv[1]))

    if snpdata.SaveVMHeader.FileVersion == 3:
        for s in snpdata.Sections:
            if s.SectionIdString == "ram":
                ramdata = s.Data
                break
    elif snpdata.SaveVMHeader.FileVersion == 4:
        for s in snpdata.Sections:
            if getattr(s, 'SectionIdString', None) == "ram":
                ramdata = RAMBlocks.parse(s.SectionData.value)
                break

    print "Sections in RAM block:"
    for block in ramdata:
        if block.MemSizeData:
            for sect in block.MemSizeData:
                print "  %-32s size = %-10s (%d bytes)" % (sect.Name, sizeof_fmt(sect.Size), sect.Size)
