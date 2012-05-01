// Option rom scanning code.
//
// Copyright (C) 2008  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2002  MandrakeSoft S.A.
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "bregs.h" // struct bregs
#include "farptr.h" // FLATPTR_TO_SEG
#include "config.h" // CONFIG_*
#include "util.h" // dprintf
#include "pci.h" // foreachpci
#include "pci_regs.h" // PCI_ROM_ADDRESS
#include "pci_ids.h" // PCI_CLASS_DISPLAY_VGA
#include "boot.h" // IPL
#include "paravirt.h" // qemu_cfg_*


/****************************************************************
 * Definitions
 ****************************************************************/

struct rom_header {
    u16 signature;
    u8 size;
    u8 initVector[4];
    u8 reserved[17];
    u16 pcioffset;
    u16 pnpoffset;
} PACKED;

struct pci_data {
    u32 signature;
    u16 vendor;
    u16 device;
    u16 vitaldata;
    u16 dlen;
    u8 drevision;
    u8 class_lo;
    u16 class_hi;
    u16 ilen;
    u16 irevision;
    u8 type;
    u8 indicator;
    u16 reserved;
} PACKED;

struct pnp_data {
    u32 signature;
    u8 revision;
    u8 len;
    u16 nextoffset;
    u8 reserved_08;
    u8 checksum;
    u32 devid;
    u16 manufacturer;
    u16 productname;
    u8 type_lo;
    u16 type_hi;
    u8 dev_flags;
    u16 bcv;
    u16 dv;
    u16 bev;
    u16 reserved_1c;
    u16 staticresource;
} PACKED;

#define OPTION_ROM_SIGNATURE 0xaa55
#define OPTION_ROM_ALIGN 2048
#define OPTION_ROM_INITVECTOR offsetof(struct rom_header, initVector[0])
#define PCI_ROM_SIGNATURE 0x52494350 // PCIR
#define PCIROM_CODETYPE_X86 0

// The end of the last deployed rom.
u32 RomEnd = BUILD_ROM_START;


/****************************************************************
 * Helper functions
 ****************************************************************/

// Execute a given option rom.
static void
__callrom(struct rom_header *rom, u16 offset, u16 bdf)
{
    u16 seg = FLATPTR_TO_SEG(rom);
    dprintf(1, "Running option rom at %04x:%04x\n", seg, offset);

    struct bregs br;
    memset(&br, 0, sizeof(br));
    br.flags = F_IF;
    br.ax = bdf;
    br.bx = 0xffff;
    br.dx = 0xffff;
    br.es = SEG_BIOS;
    br.di = get_pnp_offset();
    br.code = SEGOFF(seg, offset);
    start_preempt();
    call16big(&br);
    finish_preempt();

    debug_serial_setup();
}

// Execute a given option rom at the standard entry vector.
static void
callrom(struct rom_header *rom, u16 bdf)
{
    __callrom(rom, OPTION_ROM_INITVECTOR, bdf);
}

// Execute a BCV option rom registered via add_bcv().
void
call_bcv(u16 seg, u16 ip)
{
    __callrom(MAKE_FLATPTR(seg, 0), ip, 0);
}

static int EnforceChecksum;

// Verify that an option rom looks valid
static int
is_valid_rom(struct rom_header *rom)
{
    dprintf(6, "Checking rom %p (sig %x size %d)\n"
            , rom, rom->signature, rom->size);
    if (rom->signature != OPTION_ROM_SIGNATURE)
        return 0;
    if (! rom->size)
        return 0;
    u32 len = rom->size * 512;
    u8 sum = checksum(rom, len);
    if (sum != 0) {
        dprintf(1, "Found option rom with bad checksum: loc=%p len=%d sum=%x\n"
                , rom, len, sum);
        if (EnforceChecksum)
            return 0;
    }
    return 1;
}

// Check if a valid option rom has a pnp struct; return it if so.
static struct pnp_data *
get_pnp_rom(struct rom_header *rom)
{
    struct pnp_data *pnp = (void*)((u8*)rom + rom->pnpoffset);
    if (pnp->signature != PNP_SIGNATURE)
        return NULL;
    return pnp;
}

// Check for multiple pnp option rom headers.
static struct pnp_data *
get_pnp_next(struct rom_header *rom, struct pnp_data *pnp)
{
    if (! pnp->nextoffset)
        return NULL;
    pnp = (void*)((u8*)rom + pnp->nextoffset);
    if (pnp->signature != PNP_SIGNATURE)
        return NULL;
    return pnp;
}

// Check if a valid option rom has a pci struct; return it if so.
static struct pci_data *
get_pci_rom(struct rom_header *rom)
{
    struct pci_data *pd = (void*)((u32)rom + rom->pcioffset);
    if (pd->signature != PCI_ROM_SIGNATURE)
        return NULL;
    return pd;
}

// Return start of code in 0xc0000-0xf0000 space.
static inline u32 _max_rom(void) {
    extern u8 code32flat_start[], code32init_end[];
    return CONFIG_RELOCATE_INIT ? (u32)code32init_end : (u32)code32flat_start;
}
// Return the memory position up to which roms may be located.
static inline u32 max_rom(void) {
    u32 end = _max_rom();
    return end > BUILD_BIOS_ADDR ? BUILD_BIOS_ADDR : end;
}

// Copy a rom to its permanent location below 1MiB
static struct rom_header *
copy_rom(struct rom_header *rom)
{
    u32 romsize = rom->size * 512;
    if (RomEnd + romsize > max_rom()) {
        // Option rom doesn't fit.
        warn_noalloc();
        return NULL;
    }
    dprintf(4, "Copying option rom (size %d) from %p to %x\n"
            , romsize, rom, RomEnd);
    iomemcpy((void*)RomEnd, rom, romsize);
    return (void*)RomEnd;
}

// Run rom init code and note rom size.
static int
init_optionrom(struct rom_header *rom, u16 bdf, int isvga)
{
    if (! is_valid_rom(rom))
        return -1;

    if (isvga || get_pnp_rom(rom))
        // Only init vga and PnP roms here.
        callrom(rom, bdf);

    RomEnd = (u32)rom + ALIGN(rom->size * 512, OPTION_ROM_ALIGN);

    return 0;
}

#define RS_PCIROM (1LL<<33)

static void
setRomSource(u64 *sources, struct rom_header *rom, u64 source)
{
    if (sources)
        sources[((u32)rom - BUILD_ROM_START) / OPTION_ROM_ALIGN] = source;
}

static int
getRomPriority(u64 *sources, struct rom_header *rom, int instance)
{
    u64 source = sources[((u32)rom - BUILD_ROM_START) / OPTION_ROM_ALIGN];
    if (!source)
        return -1;
    if (source & RS_PCIROM)
        return bootprio_find_pci_rom((void*)(u32)source, instance);
    return bootprio_find_named_rom(romfile_name(source), instance);
}


/****************************************************************
 * Roms in CBFS
 ****************************************************************/

// Check if an option rom is at a hardcoded location or in CBFS.
static struct rom_header *
lookup_hardcode(struct pci_device *pci)
{
    char fname[17];
    snprintf(fname, sizeof(fname), "pci%04x,%04x.rom"
             , pci->vendor, pci->device);
    int ret = romfile_copy(romfile_find(fname), (void*)RomEnd
                           , max_rom() - RomEnd);
    if (ret <= 0)
        return NULL;
    return (void*)RomEnd;
}

// Run all roms in a given CBFS directory.
static void
run_file_roms(const char *prefix, int isvga, u64 *sources)
{
    u32 file = 0;
    for (;;) {
        file = romfile_findprefix(prefix, file);
        if (!file)
            break;
        struct rom_header *rom = (void*)RomEnd;
        int ret = romfile_copy(file, rom, max_rom() - RomEnd);
        if (ret > 0) {
            setRomSource(sources, rom, file);
            init_optionrom(rom, 0, isvga);
        }
    }
}


/****************************************************************
 * PCI roms
 ****************************************************************/

// Verify device is a vga device with legacy address decoding enabled.
static int
is_pci_vga(struct pci_device *pci)
{
    if (pci->class != PCI_CLASS_DISPLAY_VGA)
        return 0;
    u16 cmd = pci_config_readw(pci->bdf, PCI_COMMAND);
    if (!(cmd & PCI_COMMAND_IO && cmd & PCI_COMMAND_MEMORY))
        return 0;
    while (pci->parent) {
        pci = pci->parent;
        u32 ctrl = pci_config_readb(pci->bdf, PCI_BRIDGE_CONTROL);
        if (!(ctrl & PCI_BRIDGE_CTL_VGA))
            return 0;
    }
    return 1;
}

// Map the option rom of a given PCI device.
static struct rom_header *
map_pcirom(struct pci_device *pci)
{
    u16 bdf = pci->bdf;
    dprintf(6, "Attempting to map option rom on dev %02x:%02x.%x\n"
            , pci_bdf_to_bus(bdf), pci_bdf_to_dev(bdf), pci_bdf_to_fn(bdf));

    if ((pci->header_type & 0x7f) != PCI_HEADER_TYPE_NORMAL) {
        dprintf(6, "Skipping non-normal pci device (type=%x)\n"
                , pci->header_type);
        return NULL;
    }

    u32 orig = pci_config_readl(bdf, PCI_ROM_ADDRESS);
    pci_config_writel(bdf, PCI_ROM_ADDRESS, ~PCI_ROM_ADDRESS_ENABLE);
    u32 sz = pci_config_readl(bdf, PCI_ROM_ADDRESS);

    dprintf(6, "Option rom sizing returned %x %x\n", orig, sz);
    orig &= ~PCI_ROM_ADDRESS_ENABLE;
    if (!sz || sz == 0xffffffff)
        goto fail;

    if (orig == sz || (u32)(orig + 4*1024*1024) < 20*1024*1024) {
        // Don't try to map to a pci addresses at its max, in the last
        // 4MiB of ram, or the first 16MiB of ram.
        dprintf(6, "Preset rom address doesn't look valid\n");
        goto fail;
    }

    // Looks like a rom - enable it.
    pci_config_writel(bdf, PCI_ROM_ADDRESS, orig | PCI_ROM_ADDRESS_ENABLE);

    struct rom_header *rom = (void*)orig;
    for (;;) {
        dprintf(5, "Inspecting possible rom at %p (vd=%04x:%04x"
                " bdf=%02x:%02x.%x)\n"
                , rom, pci->vendor, pci->device
                , pci_bdf_to_bus(bdf), pci_bdf_to_dev(bdf), pci_bdf_to_fn(bdf));
        if (rom->signature != OPTION_ROM_SIGNATURE) {
            dprintf(6, "No option rom signature (got %x)\n", rom->signature);
            goto fail;
        }
        struct pci_data *pd = get_pci_rom(rom);
        if (! pd) {
            dprintf(6, "No valid pci signature found\n");
            goto fail;
        }

        if (pd->vendor == pci->vendor && pd->device == pci->device
            && pd->type == PCIROM_CODETYPE_X86)
            // A match
            break;
        dprintf(6, "Didn't match dev/ven (got %04x:%04x) or type (got %d)\n"
                , pd->vendor, pd->device, pd->type);
        if (pd->indicator & 0x80) {
            dprintf(6, "No more images left\n");
            goto fail;
        }
        rom = (void*)((u32)rom + pd->ilen * 512);
    }

    rom = copy_rom(rom);
    pci_config_writel(bdf, PCI_ROM_ADDRESS, orig);
    return rom;
fail:
    // Not valid - restore original and exit.
    pci_config_writel(bdf, PCI_ROM_ADDRESS, orig);
    return NULL;
}

// Attempt to map and initialize the option rom on a given PCI device.
static int
init_pcirom(struct pci_device *pci, int isvga, u64 *sources)
{
    u16 bdf = pci->bdf;
    dprintf(4, "Attempting to init PCI bdf %02x:%02x.%x (vd %04x:%04x)\n"
            , pci_bdf_to_bus(bdf), pci_bdf_to_dev(bdf), pci_bdf_to_fn(bdf)
            , pci->vendor, pci->device);
    struct rom_header *rom = lookup_hardcode(pci);
    if (! rom)
        rom = map_pcirom(pci);
    if (! rom)
        // No ROM present.
        return -1;
    setRomSource(sources, rom, RS_PCIROM | (u32)pci);
    return init_optionrom(rom, bdf, isvga);
}


/****************************************************************
 * Non-VGA option rom init
 ****************************************************************/

void
optionrom_setup(void)
{
    if (! CONFIG_OPTIONROMS)
        return;

    dprintf(1, "Scan for option roms\n");
    u64 sources[(BUILD_BIOS_ADDR - BUILD_ROM_START) / OPTION_ROM_ALIGN];
    memset(sources, 0, sizeof(sources));
    u32 post_vga = RomEnd;

    if (CONFIG_OPTIONROMS_DEPLOYED) {
        // Option roms are already deployed on the system.
        u32 pos = RomEnd;
        while (pos < max_rom()) {
            int ret = init_optionrom((void*)pos, 0, 0);
            if (ret)
                pos += OPTION_ROM_ALIGN;
            else
                pos = RomEnd;
        }
    } else {
        // Find and deploy PCI roms.
        struct pci_device *pci;
        foreachpci(pci) {
            if (pci->class == PCI_CLASS_DISPLAY_VGA || pci->have_driver)
                continue;
            init_pcirom(pci, 0, sources);
        }

        // Find and deploy CBFS roms not associated with a device.
        run_file_roms("genroms/", 0, sources);
    }

    // All option roms found and deployed - now build BEV/BCV vectors.

    u32 pos = post_vga;
    while (pos < RomEnd) {
        struct rom_header *rom = (void*)pos;
        if (! is_valid_rom(rom)) {
            pos += OPTION_ROM_ALIGN;
            continue;
        }
        pos += ALIGN(rom->size * 512, OPTION_ROM_ALIGN);
        struct pnp_data *pnp = get_pnp_rom(rom);
        if (! pnp) {
            // Legacy rom.
            boot_add_bcv(FLATPTR_TO_SEG(rom), OPTION_ROM_INITVECTOR, 0
                         , getRomPriority(sources, rom, 0));
            continue;
        }
        // PnP rom.
        if (pnp->bev) {
            // Can boot system - add to IPL list.
            boot_add_bev(FLATPTR_TO_SEG(rom), pnp->bev, pnp->productname
                         , getRomPriority(sources, rom, 0));
        } else {
            // Check for BCV (there may be multiple).
            int instance = 0;
            while (pnp && pnp->bcv) {
                boot_add_bcv(FLATPTR_TO_SEG(rom), pnp->bcv, pnp->productname
                             , getRomPriority(sources, rom, instance++));
                pnp = get_pnp_next(rom, pnp);
            }
        }
    }
}


/****************************************************************
 * VGA init
 ****************************************************************/

static int S3ResumeVgaInit;
int ScreenAndDebug;

// Call into vga code to turn on console.
void
vga_setup(void)
{
    if (! CONFIG_OPTIONROMS)
        return;

    dprintf(1, "Scan for VGA option rom\n");

    // Load some config settings that impact VGA.
    EnforceChecksum = romfile_loadint("etc/optionroms-checksum", 1);
    S3ResumeVgaInit = romfile_loadint("etc/s3-resume-vga-init", 0);
    ScreenAndDebug = romfile_loadint("etc/screen-and-debug", 1);

    if (CONFIG_OPTIONROMS_DEPLOYED) {
        // Option roms are already deployed on the system.
        init_optionrom((void*)BUILD_ROM_START, 0, 1);
    } else {
        // Clear option rom memory
        memset((void*)RomEnd, 0, max_rom() - RomEnd);

        // Find and deploy PCI VGA rom.
        struct pci_device *pci;
        foreachpci(pci) {
            if (!is_pci_vga(pci))
                continue;
            vgahook_setup(pci);
            init_pcirom(pci, 1, NULL);
            break;
        }

        // Find and deploy CBFS vga-style roms not associated with a device.
        run_file_roms("vgaroms/", 1, NULL);
    }

    if (RomEnd == BUILD_ROM_START) {
        // No VGA rom found
        RomEnd += OPTION_ROM_ALIGN;
        return;
    }

    enable_vga_console();
}

void
s3_resume_vga_init(void)
{
    if (!S3ResumeVgaInit)
        return;
    struct rom_header *rom = (void*)BUILD_ROM_START;
    if (! is_valid_rom(rom))
        return;
    callrom(rom, 0);
}
