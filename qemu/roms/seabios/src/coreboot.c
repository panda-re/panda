// Coreboot interface support.
//
// Copyright (C) 2008,2009  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "memmap.h" // add_e820
#include "util.h" // dprintf
#include "biosvar.h" // GET_EBDA
#include "lzmadecode.h" // LzmaDecode
#include "smbios.h" // smbios_init
#include "boot.h" // boot_add_cbfs


/****************************************************************
 * Memory map
 ****************************************************************/

struct cb_header {
    u32 signature;
    u32 header_bytes;
    u32 header_checksum;
    u32 table_bytes;
    u32 table_checksum;
    u32 table_entries;
};

#define CB_SIGNATURE 0x4f49424C // "LBIO"

struct cb_memory_range {
    u64 start;
    u64 size;
    u32 type;
};

#define CB_MEM_TABLE    16

struct cb_memory {
    u32 tag;
    u32 size;
    struct cb_memory_range map[0];
};

#define CB_TAG_MEMORY 0x01

#define MEM_RANGE_COUNT(_rec) \
        (((_rec)->size - sizeof(*(_rec))) / sizeof((_rec)->map[0]))

struct cb_mainboard {
    u32 tag;
    u32 size;
    u8  vendor_idx;
    u8  part_idx;
    char  strings[0];
};

#define CB_TAG_MAINBOARD 0x0003

struct cb_forward {
    u32 tag;
    u32 size;
    u64 forward;
};

#define CB_TAG_FORWARD 0x11

static u16
ipchksum(char *buf, int count)
{
    u16 *p = (u16*)buf;
    u32 sum = 0;
    while (count > 1) {
        sum += *p++;
        count -= 2;
    }
    if (count)
        sum += *(u8*)p;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

// Try to locate the coreboot header in a given address range.
static struct cb_header *
find_cb_header(char *addr, int len)
{
    char *end = addr + len;
    for (; addr < end; addr += 16) {
        struct cb_header *cbh = (struct cb_header *)addr;
        if (cbh->signature != CB_SIGNATURE)
            continue;
        if (! cbh->table_bytes)
            continue;
        if (ipchksum(addr, sizeof(*cbh)) != 0)
            continue;
        if (ipchksum(addr + sizeof(*cbh), cbh->table_bytes)
            != cbh->table_checksum)
            continue;
        return cbh;
    }
    return NULL;
}

// Try to find the coreboot memory table in the given coreboot table.
static void *
find_cb_subtable(struct cb_header *cbh, u32 tag)
{
    char *tbl = (char *)cbh + sizeof(*cbh);
    int i;
    for (i=0; i<cbh->table_entries; i++) {
        struct cb_memory *cbm = (struct cb_memory *)tbl;
        tbl += cbm->size;
        if (cbm->tag == tag)
            return cbm;
    }
    return NULL;
}

static struct cb_memory *CBMemTable;
const char *CBvendor, *CBpart;

// Populate max ram and e820 map info by scanning for a coreboot table.
static void
coreboot_fill_map(void)
{
    dprintf(3, "Attempting to find coreboot table\n");

    // Find coreboot table.
    struct cb_header *cbh = find_cb_header(0, 0x1000);
    if (!cbh)
        goto fail;
    struct cb_forward *cbf = find_cb_subtable(cbh, CB_TAG_FORWARD);
    if (cbf) {
        dprintf(3, "Found coreboot table forwarder.\n");
        cbh = find_cb_header((char *)((u32)cbf->forward), 0x100);
        if (!cbh)
            goto fail;
    }
    dprintf(3, "Now attempting to find coreboot memory map\n");
    struct cb_memory *cbm = CBMemTable = find_cb_subtable(cbh, CB_TAG_MEMORY);
    if (!cbm)
        goto fail;

    u64 maxram = 0, maxram_over4G = 0;
    int i, count = MEM_RANGE_COUNT(cbm);
    for (i=0; i<count; i++) {
        struct cb_memory_range *m = &cbm->map[i];
        u32 type = m->type;
        if (type == CB_MEM_TABLE) {
            type = E820_RESERVED;
        } else if (type == E820_ACPI || type == E820_RAM) {
            u64 end = m->start + m->size;
            if (end > 0x100000000ull) {
                end -= 0x100000000ull;
                if (end > maxram_over4G)
                    maxram_over4G = end;
            } else if (end > maxram)
                maxram = end;
        }
        add_e820(m->start, m->size, type);
    }

    RamSize = maxram;
    RamSizeOver4G = maxram_over4G;

    // Ughh - coreboot likes to set a map at 0x0000-0x1000, but this
    // confuses grub.  So, override it.
    add_e820(0, 16*1024, E820_RAM);

    struct cb_mainboard *cbmb = find_cb_subtable(cbh, CB_TAG_MAINBOARD);
    if (cbmb) {
        CBvendor = &cbmb->strings[cbmb->vendor_idx];
        CBpart = &cbmb->strings[cbmb->part_idx];
        dprintf(1, "Found mainboard %s %s\n", CBvendor, CBpart);
    }

    return;

fail:
    // No table found..  Use 16Megs as a dummy value.
    dprintf(1, "Unable to find coreboot table!\n");
    RamSize = 16*1024*1024;
    RamSizeOver4G = 0;
    add_e820(0, 16*1024*1024, E820_RAM);
    return;
}


/****************************************************************
 * BIOS table copying
 ****************************************************************/

// Attempt to find (and relocate) any standard bios tables found in a
// given address range.
static void
scan_tables(u32 start, u32 size)
{
    void *p = (void*)ALIGN(start, 16);
    void *end = (void*)start + size;
    for (; p<end; p += 16) {
        copy_pir(p);
        copy_mptable(p);
        copy_acpi_rsdp(p);
    }
}

void
coreboot_copy_biostable(void)
{
    struct cb_memory *cbm = CBMemTable;
    if (! CONFIG_COREBOOT || !cbm)
        return;

    dprintf(3, "Relocating coreboot bios tables\n");

    // Scan CB_MEM_TABLE areas for bios tables.
    int i, count = MEM_RANGE_COUNT(cbm);
    for (i=0; i<count; i++) {
        struct cb_memory_range *m = &cbm->map[i];
        if (m->type == CB_MEM_TABLE)
            scan_tables(m->start, m->size);
    }

    // XXX - just create dummy smbios table for now - should detect if
    // smbios/dmi table is found from coreboot and use that instead.
    smbios_init();
}


/****************************************************************
 * ulzma
 ****************************************************************/

// Uncompress data in flash to an area of memory.
static int
ulzma(u8 *dst, u32 maxlen, const u8 *src, u32 srclen)
{
    dprintf(3, "Uncompressing data %d@%p to %d@%p\n", srclen, src, maxlen, dst);
    CLzmaDecoderState state;
    int ret = LzmaDecodeProperties(&state.Properties, src, LZMA_PROPERTIES_SIZE);
    if (ret != LZMA_RESULT_OK) {
        dprintf(1, "LzmaDecodeProperties error - %d\n", ret);
        return -1;
    }
    u8 scratch[15980];
    int need = (LzmaGetNumProbs(&state.Properties) * sizeof(CProb));
    if (need > sizeof(scratch)) {
        dprintf(1, "LzmaDecode need %d have %d\n", need, (unsigned int)sizeof(scratch));
        return -1;
    }
    state.Probs = (CProb *)scratch;

    u32 dstlen = *(u32*)(src + LZMA_PROPERTIES_SIZE);
    if (dstlen > maxlen) {
        dprintf(1, "LzmaDecode too large (max %d need %d)\n", maxlen, dstlen);
        return -1;
    }
    u32 inProcessed, outProcessed;
    ret = LzmaDecode(&state, src + LZMA_PROPERTIES_SIZE + 8, srclen
                     , &inProcessed, dst, dstlen, &outProcessed);
    if (ret) {
        dprintf(1, "LzmaDecode returned %d\n", ret);
        return -1;
    }
    return dstlen;
}


/****************************************************************
 * Coreboot flash format
 ****************************************************************/

#define CBFS_HEADER_MAGIC 0x4F524243
#define CBFS_HEADPTR_ADDR 0xFFFFFFFc
#define CBFS_VERSION1 0x31313131

struct cbfs_header {
    u32 magic;
    u32 version;
    u32 romsize;
    u32 bootblocksize;
    u32 align;
    u32 offset;
    u32 pad[2];
} PACKED;

static struct cbfs_header *CBHDR;

static void
cbfs_setup(void)
{
    if (!CONFIG_COREBOOT || !CONFIG_COREBOOT_FLASH)
        return;

    CBHDR = *(void **)CBFS_HEADPTR_ADDR;
    if (CBHDR->magic != htonl(CBFS_HEADER_MAGIC)) {
        dprintf(1, "Unable to find CBFS (ptr=%p; got %x not %x)\n"
                , CBHDR, CBHDR->magic, htonl(CBFS_HEADER_MAGIC));
        CBHDR = NULL;
        return;
    }

    dprintf(1, "Found CBFS header at %p\n", CBHDR);
}

#define CBFS_FILE_MAGIC 0x455649484352414cLL // LARCHIVE

struct cbfs_file {
    u64 magic;
    u32 len;
    u32 type;
    u32 checksum;
    u32 offset;
    char filename[0];
} PACKED;

// Verify a cbfs entry looks valid.
static struct cbfs_file *
cbfs_verify(struct cbfs_file *file)
{
    if (file < (struct cbfs_file *)(0xFFFFFFFF - ntohl(CBHDR->romsize)))
        return NULL;
    u64 magic = file->magic;
    if (magic == CBFS_FILE_MAGIC) {
        dprintf(5, "Found CBFS file %s\n", file->filename);
        return file;
    }
    return NULL;
}

// Return the first file in the CBFS archive
static struct cbfs_file *
cbfs_getfirst(void)
{
    if (! CBHDR)
        return NULL;
    return cbfs_verify((void *)(0 - ntohl(CBHDR->romsize) + ntohl(CBHDR->offset)));
}

// Return the file after the given file.
static struct cbfs_file *
cbfs_getnext(struct cbfs_file *file)
{
    file = (void*)file + ALIGN(ntohl(file->len) + ntohl(file->offset), ntohl(CBHDR->align));
    return cbfs_verify(file);
}

// Find the file with the given filename.
struct cbfs_file *
cbfs_findfile(const char *fname)
{
    dprintf(3, "Searching CBFS for %s\n", fname);
    struct cbfs_file *file;
    for (file = cbfs_getfirst(); file; file = cbfs_getnext(file))
        if (strcmp(fname, file->filename) == 0)
            return file;
    return NULL;
}

// Find next file with the given filename prefix.
struct cbfs_file *
cbfs_findprefix(const char *prefix, struct cbfs_file *last)
{
    if (!CONFIG_COREBOOT || !CONFIG_COREBOOT_FLASH)
        return NULL;

    dprintf(3, "Searching CBFS for prefix %s\n", prefix);
    int len = strlen(prefix);
    struct cbfs_file *file;
    if (! last)
        file = cbfs_getfirst();
    else
        file = cbfs_getnext(last);
    for (; file; file = cbfs_getnext(file))
        if (memcmp(prefix, file->filename, len) == 0)
            return file;
    return NULL;
}

// Find a file with the given filename (possibly with ".lzma" extension).
struct cbfs_file *
cbfs_finddatafile(const char *fname)
{
    int fnlen = strlen(fname);
    struct cbfs_file *file = NULL;
    for (;;) {
        file = cbfs_findprefix(fname, file);
        if (!file)
            return NULL;
        if (file->filename[fnlen] == '\0'
            || strcmp(&file->filename[fnlen], ".lzma") == 0)
            return file;
    }
}

// Determine whether the file has a ".lzma" extension.
static int
cbfs_iscomp(struct cbfs_file *file)
{
    int fnamelen = strlen(file->filename);
    return fnamelen > 5 && strcmp(&file->filename[fnamelen-5], ".lzma") == 0;
}

// Return the filename of a given file.
const char *
cbfs_filename(struct cbfs_file *file)
{
    return file->filename;
}

// Determine the uncompressed size of a datafile.
u32
cbfs_datasize(struct cbfs_file *file)
{
    void *src = (void*)file + ntohl(file->offset);
    if (cbfs_iscomp(file))
        return *(u32*)(src + LZMA_PROPERTIES_SIZE);
    return ntohl(file->len);
}

// Copy a file to memory (uncompressing if necessary)
int
cbfs_copyfile(struct cbfs_file *file, void *dst, u32 maxlen)
{
    if (!CONFIG_COREBOOT || !CONFIG_COREBOOT_FLASH || !file)
        return -1;

    u32 size = ntohl(file->len);
    void *src = (void*)file + ntohl(file->offset);
    if (cbfs_iscomp(file)) {
        // Compressed - copy to temp ram and uncompress it.
        void *temp = malloc_tmphigh(size);
        if (!temp)
            return -1;
        iomemcpy(temp, src, size);
        int ret = ulzma(dst, maxlen, temp, size);
        yield();
        free(temp);
        return ret;
    }

    // Not compressed.
    dprintf(3, "Copying data %d@%p to %d@%p\n", size, src, maxlen, dst);
    if (size > maxlen) {
        warn_noalloc();
        return -1;
    }
    iomemcpy(dst, src, size);
    return size;
}

struct cbfs_payload_segment {
    u32 type;
    u32 compression;
    u32 offset;
    u64 load_addr;
    u32 len;
    u32 mem_len;
} PACKED;

#define PAYLOAD_SEGMENT_BSS    0x20535342
#define PAYLOAD_SEGMENT_ENTRY  0x52544E45

#define CBFS_COMPRESS_NONE  0
#define CBFS_COMPRESS_LZMA  1

struct cbfs_payload {
    struct cbfs_payload_segment segments[1];
};

void
cbfs_run_payload(struct cbfs_file *file)
{
    if (!CONFIG_COREBOOT || !CONFIG_COREBOOT_FLASH || !file)
        return;
    dprintf(1, "Run %s\n", file->filename);
    struct cbfs_payload *pay = (void*)file + ntohl(file->offset);
    struct cbfs_payload_segment *seg = pay->segments;
    for (;;) {
        void *src = (void*)pay + ntohl(seg->offset);
        void *dest = (void*)ntohl((u32)seg->load_addr);
        u32 src_len = ntohl(seg->len);
        u32 dest_len = ntohl(seg->mem_len);
        switch (seg->type) {
        case PAYLOAD_SEGMENT_BSS:
            dprintf(3, "BSS segment %d@%p\n", dest_len, dest);
            memset(dest, 0, dest_len);
            break;
        case PAYLOAD_SEGMENT_ENTRY: {
            dprintf(1, "Calling addr %p\n", dest);
            void (*func)() = dest;
            func();
            return;
        }
        default:
            dprintf(3, "Segment %x %d@%p -> %d@%p\n"
                    , seg->type, src_len, src, dest_len, dest);
            if (seg->compression == htonl(CBFS_COMPRESS_NONE)) {
                if (src_len > dest_len)
                    src_len = dest_len;
                memcpy(dest, src, src_len);
            } else if (CONFIG_LZMA
                       && seg->compression == htonl(CBFS_COMPRESS_LZMA)) {
                int ret = ulzma(dest, dest_len, src, src_len);
                if (ret < 0)
                    return;
                src_len = ret;
            } else {
                dprintf(1, "No support for compression type %x\n"
                        , seg->compression);
                return;
            }
            if (dest_len > src_len)
                memset(dest + src_len, 0, dest_len - src_len);
            break;
        }
        seg++;
    }
}

// Register payloads in "img/" directory with boot system.
void
cbfs_payload_setup(void)
{
    struct cbfs_file *file = NULL;
    for (;;) {
        file = cbfs_findprefix("img/", file);
        if (!file)
            break;
        const char *filename = cbfs_filename(file);
        char *desc = znprintf(MAXDESCSIZE, "Payload [%s]", &filename[4]);
        boot_add_cbfs(file, desc, bootprio_find_named_rom(filename, 0));
    }
}

void
coreboot_setup(void)
{
    coreboot_fill_map();
    cbfs_setup();
}
