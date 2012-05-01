/* lib.c
 * tag: simple function library
 *
 * Copyright (C) 2003 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#include "libc/vsprintf.h"
#include "libopenbios/bindings.h"
#include "libopenbios/ofmem.h"
#include "asm/asi.h"
#include "pgtsrmmu.h"
#include "openprom.h"
#include "libopenbios/sys_info.h"
#include "boot.h"
#include "romvec.h"

#define NCTX_SWIFT  0x100
#define LOWMEMSZ 32 * 1024 * 1024

#ifdef CONFIG_DEBUG_MEM
#define DPRINTF(fmt, args...)                   \
    do { printk(fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...)
#endif

/* Format a string and print it on the screen, just like the libc
 * function printf.
 */
int printk( const char *fmt, ... )
{
        char *p, buf[512];
	va_list args;
	int i;

	va_start(args, fmt);
        i = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	for( p=buf; *p; p++ )
		putchar(*p);
	return i;
}

/*
 * Allocatable memory chunk.
 */
struct mem {
    char *start, *uplim;
    char *curp;
};

struct mem cdvmem;              /* Current device virtual memory space */

unsigned int va_shift;
static unsigned long *context_table;
static unsigned long *l1;

static ucell *mem_reg = 0;
static ucell *mem_avail = 0;
static ucell *virt_avail = 0;

static struct linux_mlist_v0 totphys[1];
static struct linux_mlist_v0 totmap[1];
static struct linux_mlist_v0 totavail[1];

struct linux_mlist_v0 *ptphys;
struct linux_mlist_v0 *ptmap;
struct linux_mlist_v0 *ptavail;

/* Private functions for mapping between physical/virtual addresses */ 
phys_addr_t
va2pa(unsigned long va)
{
    if ((va >= (unsigned long)&_start) &&
        (va < (unsigned long)&_end))
        return va - va_shift;
    else
        return va;
}

unsigned long
pa2va(phys_addr_t pa)
{
    if ((pa + va_shift >= (unsigned long)&_start) &&
        (pa + va_shift < (unsigned long)&_end))
        return pa + va_shift;
    else
        return pa;
}

void *
malloc(int size)
{
    return ofmem_malloc(size);
}

void *
realloc( void *ptr, size_t size )
{
    return ofmem_realloc(ptr, size);
}

void
free(void *ptr)
{
    ofmem_free(ptr);
}

/*
 * Allocate memory. This is reusable.
 */
void
mem_init(struct mem *t, char *begin, char *limit)
{
    t->start = begin;
    t->uplim = limit;
    t->curp = begin;
}

void *
mem_alloc(struct mem *t, int size, int align)
{
    char *p;
    unsigned long pa;

    // The alignment restrictions refer to physical, not virtual
    // addresses
    pa = va2pa((unsigned long)t->curp) + (align - 1);
    pa &= ~(align - 1);
    p = (char *)pa2va(pa);

    if ((unsigned long)p >= (unsigned long)t->uplim ||
        (unsigned long)p + size > (unsigned long)t->uplim)
        return NULL;
    t->curp = p + size;

    return p;
}

static unsigned long
find_pte(unsigned long va, int alloc)
{
    uint32_t pte;
    void *p;
    unsigned long pa;
    int ret;

    pte = l1[(va >> SRMMU_PGDIR_SHIFT) & (SRMMU_PTRS_PER_PGD - 1)];
    if ((pte & SRMMU_ET_MASK) == SRMMU_ET_INVALID) {
        if (alloc) {
            ret = ofmem_posix_memalign(&p, SRMMU_PTRS_PER_PMD * sizeof(int),
                                 SRMMU_PTRS_PER_PMD * sizeof(int));
            if (ret != 0)
                return ret;
            pte = SRMMU_ET_PTD | ((va2pa((unsigned long)p)) >> 4);
            l1[(va >> SRMMU_PGDIR_SHIFT) & (SRMMU_PTRS_PER_PGD - 1)] = pte;
            /* barrier() */
        } else {
            return -1;
        }
    }

    pa = (pte & 0xFFFFFFF0) << 4;
    pa += ((va >> SRMMU_PMD_SHIFT) & (SRMMU_PTRS_PER_PMD - 1)) << 2;
    pte = *(uint32_t *)pa2va(pa);
    if ((pte & SRMMU_ET_MASK) == SRMMU_ET_INVALID) {
        if (alloc) {
            ret = ofmem_posix_memalign(&p, SRMMU_PTRS_PER_PTE * sizeof(void *),
                                 SRMMU_PTRS_PER_PTE * sizeof(void *));
            if (ret != 0)
                return ret;
            pte = SRMMU_ET_PTD | ((va2pa((unsigned int)p)) >> 4);
            *(uint32_t *)pa2va(pa) = pte;
        } else {
            return -2;
        }
    }

    pa = (pte & 0xFFFFFFF0) << 4;
    pa += ((va >> PAGE_SHIFT) & (SRMMU_PTRS_PER_PTE - 1)) << 2;

    return pa2va(pa);
}

static void
map_pages(phys_addr_t phys, unsigned long virt,
		  unsigned long size, unsigned long mode)
{
    unsigned long npages, off;
    uint32_t pte;
    unsigned long pa;

    DPRINTF("map_pages: va 0x%lx, pa 0x%llx, size 0x%lx\n", virt, phys, size);

    off = phys & (PAGE_SIZE - 1);
    npages = (off + (size - 1) + (PAGE_SIZE - 1)) / PAGE_SIZE;
    phys &= ~(uint64_t)(PAGE_SIZE - 1);

    while (npages-- != 0) {
        pa = find_pte(virt, 1);

        pte = SRMMU_ET_PTE | ((phys & PAGE_MASK) >> 4);
	pte |= mode;

        *(uint32_t *)pa = pte;

        virt += PAGE_SIZE;
        phys += PAGE_SIZE;
    }
}

/*
 * D5.3 pgmap@ ( va -- pte )
 */
static void
pgmap_fetch(void)
{
    uint32_t pte;
    unsigned long va, pa;

    va = POP();

    pa = find_pte(va, 0);
    if (pa == 1 || pa == 2)
        goto error;
    pte = *(uint32_t *)pa;
    DPRINTF("pgmap@: va 0x%lx pa 0x%lx pte 0x%x\n", va, pa, pte);

    PUSH(pte);
    return;
 error:
    PUSH(0);
}

/*
 * D5.3 pgmap! ( pte va -- )
 */
static void
pgmap_store(void)
{
    uint32_t pte;
    unsigned long va, pa;

    va = POP();
    pte = POP();

    pa = find_pte(va, 1);
    *(uint32_t *)pa = pte;
    DPRINTF("pgmap!: va 0x%lx pa 0x%lx pte 0x%x\n", va, pa, pte);
}

/*
 * D5.3 map-pages ( pa space va size -- )
 */
static void
ob_map_pages(void)
{
    unsigned long va;
    int size;
    uint64_t pa;

    size = POP();
    va = POP();
    pa = POP();
    pa <<= 32;
    pa |= POP() & 0xffffffff;

    map_pages(pa, va, size, ofmem_arch_default_translation_mode(pa));
    DPRINTF("map-page: va 0x%lx pa 0x%llx size 0x%x\n", va, pa, size);
}

static void
update_memory_properties(void)
{
    /* Update the device tree memory properties from the master
       totphys, totmap and totavail romvec arrays */
    mem_reg[0] = 0;
    mem_reg[1] = pointer2cell(totphys[0].start_adr);
    mem_reg[2] = totphys[0].num_bytes;

    virt_avail[0] = 0;
    virt_avail[1] = 0;
    virt_avail[2] = pointer2cell(totmap[0].start_adr);

    mem_avail[0] = 0;
    mem_avail[1] = pointer2cell(totavail[0].start_adr);
    mem_avail[2] = totavail[0].num_bytes;
}

static void
init_romvec_mem(void)
{
    ptphys = totphys;
    ptmap = totmap;
    ptavail = totavail;

    /*
     * Form memory descriptors.
     */
    totphys[0].theres_more = NULL;
    totphys[0].start_adr = (char *) 0;
    totphys[0].num_bytes = qemu_mem_size;

    totavail[0].theres_more = NULL;
    totavail[0].start_adr = (char *) 0;
    totavail[0].num_bytes = va2pa((int)&_start) - PAGE_SIZE;

    totmap[0].theres_more = NULL;
    totmap[0].start_adr = &_start;
    totmap[0].num_bytes = (unsigned long) &_iomem -
        (unsigned long) &_start + PAGE_SIZE;

    /* Pointers to device tree memory properties */
    mem_reg = malloc(sizeof(ucell) * 3);
    mem_avail = malloc(sizeof(ucell) * 3);
    virt_avail = malloc(sizeof(ucell) * 3);

    update_memory_properties();
}

char *obp_dumb_mmap(char *va, int which_io, unsigned int pa,
                    unsigned int size)
{
    uint64_t mpa = ((uint64_t)which_io << 32) | (uint64_t)pa;

    map_pages(mpa, (unsigned long)va, size, ofmem_arch_default_translation_mode(mpa));
    return va;
}

void obp_dumb_munmap(__attribute__((unused)) char *va,
                     __attribute__((unused)) unsigned int size)
{
    DPRINTF("obp_dumb_munmap: virta 0x%x, sz %d\n", (unsigned int)va, size);
}

void ofmem_arch_unmap_pages(ucell virt, ucell size)
{
    /* Currently do nothing */
}

void ofmem_arch_early_map_pages(phys_addr_t phys, ucell virt, ucell size, ucell mode)
{
    map_pages(phys, virt, size, mode);
}

char *obp_memalloc(char *va, unsigned int size, unsigned int align)
{
    phys_addr_t phys;
    ucell virt;

    /* Claim physical memory */
    phys = ofmem_claim_phys(-1, size, align);

    /* Claim virtual memory */
    virt = ofmem_claim_virt(pointer2cell(va), size, 0);

    /* Map the memory */
    ofmem_map(phys, virt, size, ofmem_arch_default_translation_mode(phys));

    return cell2pointer(virt);
}

char *obp_dumb_memalloc(char *va, unsigned int size)
{
    unsigned long align;
    int i;
    
    /* Solaris seems to assume that the returned value is physically aligned to size. For
       example, not having this here causes the Solaris 8 kernel to fault because the 
       IOMMU page table base address is calculated incorrectly. */

    /* Enforce a minimum alignment of CONFIG_OFMEM_MALLOC_ALIGN, and choose an alignment 
       which is the next power of 2 higher than the specified size */
    align = size;
    if (align <= CONFIG_OFMEM_MALLOC_ALIGN) {
        align = CONFIG_OFMEM_MALLOC_ALIGN;
    } else {
        align--;
        for (i = 1; i < sizeof(unsigned long) * 8; i<<=1) {
            align |= align >> i;
        }
        align++;
    }

    return obp_memalloc(va, size, align);
}

void obp_dumb_memfree(__attribute__((unused))char *va,
                             __attribute__((unused))unsigned sz)
{
    DPRINTF("obp_dumb_memfree 0x%p (size %d)\n", va, sz);
}

void
ob_init_mmu(void)
{
    ucell *memreg;
    ucell *virtreg;
    phys_addr_t virtregsize;
    ofmem_t *ofmem = ofmem_arch_get_private();

    init_romvec_mem();

    /* Find the phandles for the /memory and /virtual-memory nodes */
    push_str("/memory");
    fword("find-package");
    POP();
    s_phandle_memory = POP();

    push_str("/virtual-memory");
    fword("find-package");
    POP();
    s_phandle_mmu = POP();

    ofmem_register(s_phandle_memory, s_phandle_mmu);

    /* Setup /memory:reg (totphys) property */
    memreg = malloc(3 * sizeof(ucell));
    ofmem_arch_encode_physaddr(memreg, 0); /* physical base */
    memreg[2] = (ucell)ofmem->ramsize; /* size */

    push_str("/memory");
    fword("find-device");
    PUSH(pointer2cell(memreg));
    PUSH(3 * sizeof(ucell));
    push_str("reg");
    PUSH_ph(s_phandle_memory);
    fword("encode-property");

    /* Setup /virtual-memory:reg property */
    virtregsize = ((phys_addr_t)((ucell)-1) + 1) / 2;
    
    virtreg = malloc(6 * sizeof(ucell));
    ofmem_arch_encode_physaddr(virtreg, 0);
    virtreg[2] = virtregsize;
    ofmem_arch_encode_physaddr(&virtreg[3], virtregsize);
    virtreg[5] = virtregsize;
    
    push_str("/virtual-memory");
    fword("find-device");
    PUSH(pointer2cell(virtreg));
    PUSH(6 * sizeof(ucell));
    push_str("reg");
    PUSH_ph(s_phandle_mmu);
    fword("encode-property");
    
    PUSH(0);
    fword("active-package!");
    bind_func("pgmap@", pgmap_fetch);
    bind_func("pgmap!", pgmap_store);
    bind_func("map-pages", ob_map_pages);
}

/*
 * Switch page tables.
 */
void
init_mmu_swift(void)
{
    unsigned int addr, i;
    unsigned long pa, va;
    int size;

    ofmem_posix_memalign((void *)&context_table, NCTX_SWIFT * sizeof(int),
                   NCTX_SWIFT * sizeof(int));
    ofmem_posix_memalign((void *)&l1, 256 * sizeof(int), 256 * sizeof(int));

    context_table[0] = (((unsigned long)va2pa((unsigned long)l1)) >> 4) |
        SRMMU_ET_PTD;

    for (i = 1; i < NCTX_SWIFT; i++) {
        context_table[i] = SRMMU_ET_INVALID;
    }
    for (i = 0; i < 256; i += 4) {
        l1[i] = SRMMU_ET_INVALID;
    }

    // text, rodata, data, and bss mapped to end of RAM
    va = (unsigned long)&_start;
    size = (unsigned long)&_end - (unsigned long)&_start;
    pa = va2pa(va);
    map_pages(pa, va, size, ofmem_arch_default_translation_mode(pa));

    // 1:1 mapping for RAM
    map_pages(0, 0, LOWMEMSZ, ofmem_arch_default_translation_mode(0));

    /*
     * Flush cache
     */
    for (addr = 0; addr < 0x2000; addr += 0x10) {
        __asm__ __volatile__ ("sta %%g0, [%0] %1\n\t" : :
                              "r" (addr), "i" (ASI_M_DATAC_TAG));
        __asm__ __volatile__ ("sta %%g0, [%0] %1\n\t" : :
                              "r" (addr<<1), "i" (ASI_M_TXTC_TAG));
    }
    srmmu_set_context(0);
    srmmu_set_ctable_ptr(va2pa((unsigned long)context_table));
    srmmu_flush_whole_tlb();
}
