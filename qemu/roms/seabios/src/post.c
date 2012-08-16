// 32bit code to Power On Self Test (POST) a machine.
//
// Copyright (C) 2008-2010  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2002  MandrakeSoft S.A.
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "ioport.h" // PORT_*
#include "config.h" // CONFIG_*
#include "cmos.h" // CMOS_*
#include "util.h" // memset
#include "biosvar.h" // struct bios_data_area_s
#include "disk.h" // floppy_drive_setup
#include "ata.h" // ata_setup
#include "ahci.h" // ahci_setup
#include "memmap.h" // add_e820
#include "pic.h" // pic_setup
#include "pci.h" // create_pirtable
#include "acpi.h" // acpi_bios_init
#include "bregs.h" // struct bregs
#include "mptable.h" // mptable_init
#include "boot.h" // IPL
#include "usb.h" // usb_setup
#include "smbios.h" // smbios_init
#include "paravirt.h" // qemu_cfg_port_probe
#include "xen.h" // xen_probe_hvm_info
#include "ps2port.h" // ps2port_setup
#include "virtio-blk.h" // virtio_blk_setup


/****************************************************************
 * BIOS init
 ****************************************************************/

static void
init_ivt(void)
{
    dprintf(3, "init ivt\n");

    // Initialize all vectors to the default handler.
    int i;
    for (i=0; i<256; i++)
        SET_IVT(i, FUNC16(entry_iret_official));

    // Initialize all hw vectors to a default hw handler.
    for (i=0x08; i<=0x0f; i++)
        SET_IVT(i, FUNC16(entry_hwpic1));
    for (i=0x70; i<=0x77; i++)
        SET_IVT(i, FUNC16(entry_hwpic2));

    // Initialize software handlers.
    SET_IVT(0x02, FUNC16(entry_02));
    SET_IVT(0x10, FUNC16(entry_10));
    SET_IVT(0x11, FUNC16(entry_11));
    SET_IVT(0x12, FUNC16(entry_12));
    SET_IVT(0x13, FUNC16(entry_13_official));
    SET_IVT(0x14, FUNC16(entry_14));
    SET_IVT(0x15, FUNC16(entry_15));
    SET_IVT(0x16, FUNC16(entry_16));
    SET_IVT(0x17, FUNC16(entry_17));
    SET_IVT(0x18, FUNC16(entry_18));
    SET_IVT(0x19, FUNC16(entry_19_official));
    SET_IVT(0x1a, FUNC16(entry_1a));
    SET_IVT(0x40, FUNC16(entry_40));

    // INT 60h-66h reserved for user interrupt
    for (i=0x60; i<=0x66; i++)
        SET_IVT(i, SEGOFF(0, 0));

    // set vector 0x79 to zero
    // this is used by 'gardian angel' protection system
    SET_IVT(0x79, SEGOFF(0, 0));

    SET_IVT(0x1E, SEGOFF(SEG_BIOS, (u32)&diskette_param_table2 - BUILD_BIOS_ADDR));
}

static void
init_bda(void)
{
    dprintf(3, "init bda\n");

    struct bios_data_area_s *bda = MAKE_FLATPTR(SEG_BDA, 0);
    memset(bda, 0, sizeof(*bda));

    int esize = EBDA_SIZE_START;
    SET_BDA(mem_size_kb, BUILD_LOWRAM_END/1024 - esize);
    u16 ebda_seg = EBDA_SEGMENT_START;
    SET_BDA(ebda_seg, ebda_seg);

    // Init ebda
    struct extended_bios_data_area_s *ebda = get_ebda_ptr();
    memset(ebda, 0, sizeof(*ebda));
    ebda->size = esize;

    add_e820((u32)MAKE_FLATPTR(ebda_seg, 0), GET_EBDA2(ebda_seg, size) * 1024
             , E820_RESERVED);
}

static void
ram_probe(void)
{
    dprintf(3, "Find memory size\n");
    if (CONFIG_COREBOOT) {
        coreboot_setup();
    } else if (usingXen()) {
	xen_setup();
    } else {
        // On emulators, get memory size from nvram.
        u32 rs = ((inb_cmos(CMOS_MEM_EXTMEM2_LOW) << 16)
                  | (inb_cmos(CMOS_MEM_EXTMEM2_HIGH) << 24));
        if (rs)
            rs += 16 * 1024 * 1024;
        else
            rs = (((inb_cmos(CMOS_MEM_EXTMEM_LOW) << 10)
                   | (inb_cmos(CMOS_MEM_EXTMEM_HIGH) << 18))
                  + 1 * 1024 * 1024);
        RamSize = rs;
        add_e820(0, rs, E820_RAM);

        // Check for memory over 4Gig
        u64 high = ((inb_cmos(CMOS_MEM_HIGHMEM_LOW) << 16)
                    | ((u32)inb_cmos(CMOS_MEM_HIGHMEM_MID) << 24)
                    | ((u64)inb_cmos(CMOS_MEM_HIGHMEM_HIGH) << 32));
        RamSizeOver4G = high;
        add_e820(0x100000000ull, high, E820_RAM);

        /* reserve 256KB BIOS area at the end of 4 GB */
        add_e820(0xfffc0000, 256*1024, E820_RESERVED);
    }

    // Don't declare any memory between 0xa0000 and 0x100000
    add_e820(BUILD_LOWRAM_END, BUILD_BIOS_ADDR-BUILD_LOWRAM_END, E820_HOLE);

    // Mark known areas as reserved.
    add_e820(BUILD_BIOS_ADDR, BUILD_BIOS_SIZE, E820_RESERVED);

    u32 count = qemu_cfg_e820_entries();
    if (count) {
        struct e820_reservation entry;
        int i;

        for (i = 0; i < count; i++) {
            qemu_cfg_e820_load_next(&entry);
            add_e820(entry.address, entry.length, entry.type);
        }
    } else if (kvm_para_available()) {
        // Backwards compatibility - provide hard coded range.
        // 4 pages before the bios, 3 pages for vmx tss pages, the
        // other page for EPT real mode pagetable
        add_e820(0xfffbc000, 4*4096, E820_RESERVED);
    }

    dprintf(1, "Ram Size=0x%08x (0x%08x%08x high)\n"
            , RamSize, (u32)(RamSizeOver4G >> 32), (u32)RamSizeOver4G);
}

static void
init_bios_tables(void)
{
    if (CONFIG_COREBOOT) {
        coreboot_copy_biostable();
        return;
    }
    if (usingXen()) {
	xen_copy_biostables();
	return;
    }

    create_pirtable();

    mptable_init();

    smbios_init();

    acpi_bios_init();
}

// Initialize hardware devices
static void
init_hw(void)
{
    usb_setup();
    ps2port_setup();
    lpt_setup();
    serial_setup();

    floppy_setup();
    ata_setup();
    ahci_setup();
    cbfs_payload_setup();
    ramdisk_setup();
    virtio_blk_setup();
}

// Begin the boot process by invoking an int0x19 in 16bit mode.
void VISIBLE32FLAT
startBoot(void)
{
    // Clear low-memory allocations (required by PMM spec).
    memset((void*)BUILD_STACK_ADDR, 0, BUILD_EBDA_MINIMUM - BUILD_STACK_ADDR);

    dprintf(3, "Jump to int19\n");
    struct bregs br;
    memset(&br, 0, sizeof(br));
    br.flags = F_IF;
    call16_int(0x19, &br);
}

// Main setup code.
static void
maininit(void)
{
    // Running at new code address - do code relocation fixups
    malloc_fixupreloc();

    // Setup ivt/bda/ebda
    init_ivt();
    init_bda();

    // Init base pc hardware.
    pic_setup();
    timer_setup();
    mathcp_setup();

    // Initialize mtrr
    mtrr_setup();

    // Initialize pci
    pci_setup();
    smm_init();

    // Setup Xen hypercalls
    xen_init_hypercalls();

    // Initialize internal tables
    boot_setup();

    // Start hardware initialization (if optionrom threading)
    if (CONFIG_THREADS && CONFIG_THREAD_OPTIONROMS)
        init_hw();

    // Find and initialize other cpus
    smp_probe();

    // Setup interfaces that option roms may need
    bios32_setup();
    pmm_setup();
    pnp_setup();
    kbd_setup();
    mouse_setup();
    init_bios_tables();

    // Run vga option rom
    vga_setup();

    // Do hardware initialization (if running synchronously)
    if (!CONFIG_THREADS || !CONFIG_THREAD_OPTIONROMS) {
        init_hw();
        wait_threads();
    }

    // Run option roms
    optionrom_setup();

    // Run BCVs and show optional boot menu
    boot_prep();

    // Finalize data structures before boot
    cdemu_setup();
    pmm_finalize();
    malloc_finalize();
    memmap_finalize();

    // Setup bios checksum.
    BiosChecksum -= checksum((u8*)BUILD_BIOS_ADDR, BUILD_BIOS_SIZE);

    // Write protect bios memory.
    make_bios_readonly();

    // Invoke int 19 to start boot process.
    startBoot();
}


/****************************************************************
 * POST entry and code relocation
 ****************************************************************/

// Update given relocs for the code at 'dest' with a given 'delta'
static void
updateRelocs(void *dest, u32 *rstart, u32 *rend, u32 delta)
{
    u32 *reloc;
    for (reloc = rstart; reloc < rend; reloc++)
        *((u32*)(dest + *reloc)) += delta;
}

// Relocate init code and then call maininit() at new address.
static void
reloc_init(void)
{
    if (!CONFIG_RELOCATE_INIT) {
        maininit();
        return;
    }
    // Symbols populated by the build.
    extern u8 code32flat_start[];
    extern u8 _reloc_min_align[];
    extern u32 _reloc_abs_start[], _reloc_abs_end[];
    extern u32 _reloc_rel_start[], _reloc_rel_end[];
    extern u32 _reloc_init_start[], _reloc_init_end[];
    extern u8 code32init_start[], code32init_end[];

    // Allocate space for init code.
    u32 initsize = code32init_end - code32init_start;
    u32 align = (u32)&_reloc_min_align;
    void *dest = memalign_tmp(align, initsize);
    if (!dest)
        panic("No space for init relocation.\n");

    // Copy code and update relocs (init absolute, init relative, and runtime)
    dprintf(1, "Relocating init from %p to %p (size %d)\n"
            , code32init_start, dest, initsize);
    s32 delta = dest - (void*)code32init_start;
    memcpy(dest, code32init_start, initsize);
    updateRelocs(dest, _reloc_abs_start, _reloc_abs_end, delta);
    updateRelocs(dest, _reloc_rel_start, _reloc_rel_end, -delta);
    updateRelocs(code32flat_start, _reloc_init_start, _reloc_init_end, delta);

    // Call maininit() in relocated code.
    void (*func)(void) = (void*)maininit + delta;
    barrier();
    func();
}

// Start of Power On Self Test (POST) - the BIOS initilization phase.
// This function does the setup needed for code relocation, and then
// invokes the relocation and main setup code.
void VISIBLE32INIT
handle_post(void)
{
    debug_serial_setup();
    dprintf(1, "Start bios (version %s)\n", VERSION);

    // Enable CPU caching
    setcr0(getcr0() & ~(CR0_CD|CR0_NW));

    // Clear CMOS reboot flag.
    outb_cmos(0, CMOS_RESET_CODE);

    // Make sure legacy DMA isn't running.
    init_dma();

    // Check if we are running under Xen.
    xen_probe();

    // Allow writes to modify bios area (0xf0000)
    make_bios_writable();
    HaveRunPost = 1;

    // Detect ram and setup internal malloc.
    qemu_cfg_port_probe();
    ram_probe();
    malloc_setup();

    // Relocate initialization code and call maininit().
    reloc_init();
}
