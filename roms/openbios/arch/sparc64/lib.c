/* lib.c
 * tag: simple function library
 *
 * Copyright (C) 2003 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#include "config.h"
#include "libc/vsprintf.h"
#include "libopenbios/bindings.h"
#include "spitfire.h"
#include "libopenbios/sys_info.h"
#include "boot.h"

#include "ofmem_sparc64.h"

static ucell *va2ttedata = 0;

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

void *malloc(int size)
{
	return ofmem_malloc(size);
}

void* realloc( void *ptr, size_t size )
{
	return ofmem_realloc(ptr, size);
}

void free(void *ptr)
{
	ofmem_free(ptr);
}

#define PAGE_SIZE_4M   (4 * 1024 * 1024)
#define PAGE_SIZE_512K (512 * 1024)
#define PAGE_SIZE_64K  (64 * 1024)
#define PAGE_SIZE_8K   (8 * 1024)
#define PAGE_MASK_4M   (4 * 1024 * 1024 - 1)
#define PAGE_MASK_512K (512 * 1024 - 1)
#define PAGE_MASK_64K  (64 * 1024 - 1)
#define PAGE_MASK_8K   (8 * 1024 - 1)

static void
mmu_open(void)
{
    RET(-1);
}

static void
mmu_close(void)
{
}

void ofmem_walk_boot_map(translation_entry_cb cb)
{
    unsigned long phys, virt, size, mode, data, mask;
    unsigned int i;

    for (i = 0; i < 64; i++) {
        data = spitfire_get_dtlb_data(i);
        if (data & SPITFIRE_TTE_VALID) {
            switch ((data >> 61) & 3) {
            default:
            case 0x0: /* 8k */
                mask = 0xffffffffffffe000ULL;
                size = PAGE_SIZE_8K;
                break;
            case 0x1: /* 64k */
                mask = 0xffffffffffff0000ULL;
                size = PAGE_SIZE_64K;
                break;
            case 0x2: /* 512k */
                mask = 0xfffffffffff80000ULL;
                size = PAGE_SIZE_512K;
                break;
            case 0x3: /* 4M */
                mask = 0xffffffffffc00000ULL;
                size = PAGE_SIZE_4M;
                break;
            }

            virt = spitfire_get_dtlb_tag(i);
            virt &= mask;

            /* extract 41bit physical address */
            phys = data & 0x000001fffffff000ULL;
			phys &= mask;

			mode = data & 0xfff;

			cb(phys, virt, size, mode);
        }
    }
}

/*
  3.6.5 translate
  ( virt -- false | phys.lo ... phys.hi mode true )
*/
static void
mmu_translate(void)
{
    ucell virt, mode;
    phys_addr_t phys;

    virt = POP();

    phys = ofmem_translate(virt, &mode);

    if (phys != -1UL) {
		PUSH(phys & 0xffffffff);
		PUSH(phys >> 32);
		PUSH(mode);
		PUSH(-1);
    }
    else {
    	PUSH(0);
    }
}

/*
 * D5.3 pgmap@ ( va -- tte )
 */
static void
pgmap_fetch(void)
{
	translation_t *t = *g_ofmem_translations;
	unsigned long va, tte_data;

	va = POP();

	/* Search the ofmem linked list for this virtual address */
	while (t != NULL) {
		/* Find the correct range */
		if (va >= t->virt && va < (t->virt + t->size)) {

			/* valid tte, 8k size */
			tte_data = SPITFIRE_TTE_VALID;

			/* mix in phys address mode */
			tte_data |= t->mode;

			/* mix in page physical address = t->phys + offset */
			tte_data |= t->phys + (va - t->virt);

			/* return tte_data */
			PUSH(tte_data);

			return;
		}
		t = t->next;
	}

	/* If we get here, there was no entry */
	PUSH(0);
}

static void
dtlb_load2(unsigned long vaddr, unsigned long tte_data)
{
    asm("stxa %0, [%1] %2\n"
        "stxa %3, [%%g0] %4\n"
        : : "r" (vaddr), "r" (48), "i" (ASI_DMMU),
          "r" (tte_data), "i" (ASI_DTLB_DATA_IN));
}

static void
dtlb_load3(unsigned long vaddr, unsigned long tte_data,
           unsigned long tte_index)
{
    asm("stxa %0, [%1] %2\n"
        "stxa %3, [%4] %5\n"
        : : "r" (vaddr), "r" (48), "i" (ASI_DMMU),
          "r" (tte_data), "r" (tte_index << 3), "i" (ASI_DTLB_DATA_ACCESS));
}

static unsigned long
dtlb_faultva(void)
{
    unsigned long faultva;

    asm("ldxa [%1] %2, %0\n"
        : "=r" (faultva)
        : "r" (48), "i" (ASI_DMMU));

    return faultva;
}

/*
  ( index tte_data vaddr -- ? )
*/
static void
dtlb_load(void)
{
    unsigned long vaddr, tte_data, idx;

    vaddr = POP();
    tte_data = POP();
    idx = POP();
    dtlb_load3(vaddr, tte_data, idx);
}

/* MMU D-TLB miss handler */
void
dtlb_miss_handler(void)
{
	unsigned long faultva, tte_data = 0;

	/* Grab fault address from MMU and round to nearest 8k page */
	faultva = dtlb_faultva();
	faultva >>= 13;
	faultva <<= 13;

	/* If a valid va>tte-data routine has been set, invoke that Forth xt instead */
	if (va2ttedata && *va2ttedata != 0) {

		/* va>tte-data ( addr cnum -- false | tte-data true ) */
		PUSH(faultva);
		PUSH(0);
		enterforth(*va2ttedata);

		/* Check the result first... */
		tte_data = POP();
		if (!tte_data) {
			bug();
		} else {
			/* Grab the real data */
			tte_data = POP();
		}		
	} else {
		/* Search the ofmem linked list for this virtual address */
		PUSH(faultva);
		pgmap_fetch();
		tte_data = POP();
	}

	if (tte_data) {
		/* Update MMU */
		dtlb_load2(faultva, tte_data);
	} else {
		/* If we got here, there was no translation so fail */
		bug();
	}

}

static void
itlb_load2(unsigned long vaddr, unsigned long tte_data)
{
    asm("stxa %0, [%1] %2\n"
        "stxa %3, [%%g0] %4\n"
        : : "r" (vaddr), "r" (48), "i" (ASI_IMMU),
          "r" (tte_data), "i" (ASI_ITLB_DATA_IN));
}

static void
itlb_load3(unsigned long vaddr, unsigned long tte_data,
           unsigned long tte_index)
{
    asm("stxa %0, [%1] %2\n"
        "stxa %3, [%4] %5\n"
        : : "r" (vaddr), "r" (48), "i" (ASI_IMMU),
          "r" (tte_data), "r" (tte_index << 3), "i" (ASI_ITLB_DATA_ACCESS));
}

/*
  ( index tte_data vaddr -- ? )
*/
static void
itlb_load(void)
{
    unsigned long vaddr, tte_data, idx;

    vaddr = POP();
    tte_data = POP();
    idx = POP();
    itlb_load3(vaddr, tte_data, idx);
}

static unsigned long
itlb_faultva(void)
{
    unsigned long faultva;

    asm("ldxa [%1] %2, %0\n"
        : "=r" (faultva)
        : "r" (48), "i" (ASI_IMMU));

    return faultva;
}

/* MMU I-TLB miss handler */
void
itlb_miss_handler(void)
{
	unsigned long faultva, tte_data = 0;

	/* Grab fault address from MMU and round to nearest 8k page */
	faultva = itlb_faultva();
	faultva >>= 13;
	faultva <<= 13;

	/* If a valid va>tte-data routine has been set, invoke that Forth xt instead */
	if (va2ttedata && *va2ttedata != 0) {

		/* va>tte-data ( addr cnum -- false | tte-data true ) */
		PUSH(faultva);
		PUSH(0);
		enterforth(*va2ttedata);

		/* Check the result first... */
		tte_data = POP();
		if (!tte_data) {
			bug();
		} else {
			/* Grab the real data */
			tte_data = POP();
		}		
	} else {
		/* Search the ofmem linked list for this virtual address */
		PUSH(faultva);
		pgmap_fetch();
		tte_data = POP();
	}

	if (tte_data) {
		/* Update MMU */
		itlb_load2(faultva, tte_data);
	} else {
		/* If we got here, there was no translation so fail */
		bug();
	}
}

static void
map_pages(phys_addr_t phys, unsigned long virt,
		  unsigned long size, unsigned long mode)
{
	unsigned long tte_data, currsize;

	/* aligned to 8k page */
	size = (size + PAGE_MASK_8K) & ~PAGE_MASK_8K;

	while (size > 0) {
        currsize = size;
        if (currsize >= PAGE_SIZE_4M &&
            (virt & PAGE_MASK_4M) == 0 &&
            (phys & PAGE_MASK_4M) == 0) {
            currsize = PAGE_SIZE_4M;
            tte_data = 6ULL << 60;
        } else if (currsize >= PAGE_SIZE_512K &&
                   (virt & PAGE_MASK_512K) == 0 &&
                   (phys & PAGE_MASK_512K) == 0) {
            currsize = PAGE_SIZE_512K;
            tte_data = 4ULL << 60;
        } else if (currsize >= PAGE_SIZE_64K &&
                   (virt & PAGE_MASK_64K) == 0 &&
                   (phys & PAGE_MASK_64K) == 0) {
            currsize = PAGE_SIZE_64K;
            tte_data = 2ULL << 60;
        } else {
            currsize = PAGE_SIZE_8K;
            tte_data = 0;
        }

        tte_data |= phys | mode | SPITFIRE_TTE_VALID;

        itlb_load2(virt, tte_data);
        dtlb_load2(virt, tte_data);

        size -= currsize;
        phys += currsize;
        virt += currsize;
    }
}

void ofmem_map_pages(phys_addr_t phys, ucell virt, ucell size, ucell mode)
{
	return map_pages(phys, virt, size, mode);
}

/*
  3.6.5 map
  ( phys.lo ... phys.hi virt size mode -- )
*/
static void
mmu_map(void)
{
    ucell virt, size, mode;
    phys_addr_t phys;

    mode = POP();
    size = POP();
    virt = POP();
    phys = POP();
    phys <<= 32;
    phys |= POP();

    ofmem_map(phys, virt, size, mode);
}

static void
itlb_demap(unsigned long vaddr)
{
    asm("stxa %0, [%0] %1\n"
        : : "r" (vaddr), "i" (ASI_IMMU_DEMAP));
}

static void
dtlb_demap(unsigned long vaddr)
{
    asm("stxa %0, [%0] %1\n"
        : : "r" (vaddr), "i" (ASI_DMMU_DEMAP));
}

static void
unmap_pages(ucell virt, ucell size)
{
	ucell va;

    /* align address to 8k */
    virt &= ~PAGE_MASK_8K;

    /* align size to 8k */
    size = (size + PAGE_MASK_8K) & ~PAGE_MASK_8K;

    for (va = virt; va < virt + size; va += PAGE_SIZE_8K) {
        itlb_demap(va);
        dtlb_demap(va);
    }
}

void ofmem_arch_unmap_pages(ucell virt, ucell size)
{
	unmap_pages(virt, size);
}

void ofmem_arch_early_map_pages(phys_addr_t phys, ucell virt, ucell size, ucell mode)
{
	if (mode & SPITFIRE_TTE_LOCKED) {
		// install locked tlb entries now
		ofmem_map_pages(phys, virt, size, mode);
	}
}

/*
  3.6.5 unmap
  ( virt size -- )
*/
static void
mmu_unmap(void)
{
    ucell virt, size;

    size = POP();
    virt = POP();
    ofmem_unmap(virt, size);
}

/*
  3.6.5 claim
  ( virt size align -- base )
*/
static void
mmu_claim(void)
{
    ucell virt=-1UL, size, align;

    align = POP();
    size = POP();
    if (!align) {
    	virt = POP();
    }

    virt = ofmem_claim_virt(virt, size, align);

    PUSH(virt);
}

/*
  3.6.5 release
  ( virt size -- )
*/
static void
mmu_release(void)
{
    ucell virt, size;

    size = POP();
    virt = POP();

    ofmem_release_virt(virt, size);
}

/* ( phys size align --- base ) */
static void
mem_claim( void )
{
    ucell size, align;
    phys_addr_t phys=-1UL;

    align = POP();
    size = POP();
    if (!align) {
        phys = POP();
        phys <<= 32;
        phys |= POP();
    }

    phys = ofmem_claim_phys(phys, size, align);

    PUSH(phys & 0xffffffffUL);
    PUSH(phys >> 32);
}

/* ( phys size --- ) */
static void
mem_release( void )
{
    phys_addr_t phys;
    ucell size;

    size = POP();
    phys = POP();
    phys <<= 32;
    phys |= POP();

    ofmem_release_phys(phys, size);
}

/* ( name-cstr phys size align --- phys ) */
static void
mem_retain ( void )
{
    ucell size, align;
    phys_addr_t phys=-1UL;

    align = POP();
    size = POP();
    if (!align) {
        phys = POP();
        phys <<= 32;
        phys |= POP();
    }

    /* Currently do nothing with the name */
    POP();

    phys = ofmem_retain(phys, size, align);

    PUSH(phys & 0xffffffffUL);
    PUSH(phys >> 32);
}

/* ( virt size align -- baseaddr|-1 ) */
static void
ciface_claim( void )
{
	ucell align = POP();
	ucell size = POP();
	ucell virt = POP();
	ucell ret = ofmem_claim( virt, size, align );

	/* printk("ciface_claim: %08x %08x %x\n", virt, size, align ); */
	PUSH( ret );
}

/* ( virt size -- ) */
static void
ciface_release( void )
{
	ucell size = POP();
	ucell virt = POP();
	ofmem_release(virt, size);
}

DECLARE_NODE(memory, INSTALL_OPEN, 0, "/memory");

NODE_METHODS( memory ) = {
    { "claim",              mem_claim       },
    { "release",            mem_release     },
    { "SUNW,retain",        mem_retain      },
};

DECLARE_NODE(mmu, INSTALL_OPEN, 0, "/virtual-memory");

NODE_METHODS(mmu) = {
    { "open",               mmu_open              },
    { "close",              mmu_close             },
    { "translate",          mmu_translate         },
    { "SUNW,dtlb-load",     dtlb_load             },
    { "SUNW,itlb-load",     itlb_load             },
    { "map",                mmu_map               },
    { "unmap",              mmu_unmap             },
    { "claim",              mmu_claim             },
    { "release",            mmu_release           },
};

void ob_mmu_init(const char *cpuname, uint64_t ram_size)
{
    /* memory node */
    REGISTER_NODE_METHODS(memory, "/memory");

    /* MMU node */
    REGISTER_NODE_METHODS(mmu, "/virtual-memory");

    ofmem_register(find_dev("/memory"), find_dev("/virtual-memory"));

    push_str("/chosen");
    fword("find-device");

    push_str("/virtual-memory");
    fword("open-dev");
    fword("encode-int");
    push_str("mmu");
    fword("property");

    push_str("/memory");
    fword("find-device");

    /* All memory: 0 to RAM_size */
    PUSH(0);
    fword("encode-int");
    PUSH(0);
    fword("encode-int");
    fword("encode+");
    PUSH((int)(ram_size >> 32));
    fword("encode-int");
    fword("encode+");
    PUSH((int)(ram_size & 0xffffffff));
    fword("encode-int");
    fword("encode+");
    push_str("reg");
    fword("property");

    push_str("/openprom/client-services");
    fword("find-device");
    bind_func("cif-claim", ciface_claim);
    bind_func("cif-release", ciface_release);

    /* Other MMU functions */
    PUSH(0);
    fword("active-package!");
    bind_func("pgmap@", pgmap_fetch);

    /* Find address of va2ttedata defer word contents for MMU miss handlers */
    va2ttedata = (ucell *)findword("va>tte-data");
    va2ttedata++;
}
