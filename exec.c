/*
 *  Virtual page mapping
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#ifndef _WIN32
#endif

#include "qemu/cutils.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "tcg.h"
#include "hw/qdev-core.h"
#if !defined(CONFIG_USER_ONLY)
#include "hw/boards.h"
#include "hw/xen/xen.h"
#endif
#include "sysemu/kvm.h"
#include "sysemu/sysemu.h"
#include "qemu/timer.h"
#include "qemu/config-file.h"
#include "qemu/error-report.h"
#if defined(CONFIG_USER_ONLY)
#include "qemu.h"
#else /* !CONFIG_USER_ONLY */
#include "hw/hw.h"
#include "exec/memory.h"
#include "exec/ioport.h"
#include "sysemu/dma.h"
#include "sysemu/numa.h"
#include "sysemu/hw_accel.h"
#include "exec/address-spaces.h"
#include "sysemu/xen-mapcache.h"
#include "trace-root.h"

#include "panda/rr/rr_log.h"

#ifdef CONFIG_FALLOCATE_PUNCH_HOLE
#include <fcntl.h>
#include <linux/falloc.h>
#endif

#endif
#include "exec/cpu-all.h"
#include "qemu/rcu_queue.h"
#include "qemu/main-loop.h"
#include "translate-all.h"
#include "sysemu/replay.h"

#include "exec/memory-internal.h"
#include "exec/ram_addr.h"
#include "exec/log.h"

#include "migration/vmstate.h"

#include "qemu/range.h"
#ifndef _WIN32
#include "qemu/mmap-alloc.h"
#endif

#include <zlib.h>
#include "panda/callback_support.h"
#include "panda/checkpoint.h"

//#define DEBUG_SUBPAGE

#if !defined(CONFIG_USER_ONLY)
/* ram_list is read under rcu_read_lock()/rcu_read_unlock().  Writes
 * are protected by the ramlist lock.
 */
RAMList ram_list = { .blocks = QLIST_HEAD_INITIALIZER(ram_list.blocks) };

static MemoryRegion *system_memory;
static MemoryRegion *system_io;

AddressSpace address_space_io;
AddressSpace address_space_memory;

MemoryRegion io_mem_rom, io_mem_notdirty;
static MemoryRegion io_mem_unassigned;

/* RAM is pre-allocated and passed into qemu_ram_alloc_from_ptr */
#define RAM_PREALLOC   (1 << 0)

/* RAM is mmap-ed with MAP_SHARED */
#define RAM_SHARED     (1 << 1)

/* Only a portion of RAM (used_length) is actually used, and migrated.
 * This used_length size can change across reboots.
 */
#define RAM_RESIZEABLE (1 << 2)

#endif

#ifdef TARGET_PAGE_BITS_VARY
int target_page_bits;
bool target_page_bits_decided;
#endif

struct CPUTailQ cpus = QTAILQ_HEAD_INITIALIZER(cpus);
/* current CPU in the current thread. It is only valid inside
   cpu_exec() */
__thread CPUState *current_cpu;
/* 0 = Do not count executed instructions.
   1 = Precise instruction counting.
   2 = Adaptive rate instruction counting.  */
int use_icount;

bool set_preferred_target_page_bits(int bits)
{
    /* The target page size is the lowest common denominator for all
     * the CPUs in the system, so we can only make it smaller, never
     * larger. And we can't make it smaller once we've committed to
     * a particular size.
     */
#ifdef TARGET_PAGE_BITS_VARY
    assert(bits >= TARGET_PAGE_BITS_MIN);
    if (target_page_bits == 0 || target_page_bits > bits) {
        if (target_page_bits_decided) {
            return false;
        }
        target_page_bits = bits;
    }
#endif
    return true;
}

#if !defined(CONFIG_USER_ONLY)

static void finalize_target_page_bits(void)
{
#ifdef TARGET_PAGE_BITS_VARY
    if (target_page_bits == 0) {
        target_page_bits = TARGET_PAGE_BITS_MIN;
    }
    target_page_bits_decided = true;
#endif
}

typedef struct PhysPageEntry PhysPageEntry;

struct PhysPageEntry {
    /* How many bits skip to next level (in units of L2_SIZE). 0 for a leaf. */
    uint32_t skip : 6;
     /* index into phys_sections (!skip) or phys_map_nodes (skip) */
    uint32_t ptr : 26;
};

#define PHYS_MAP_NODE_NIL (((uint32_t)~0) >> 6)

/* Size of the L2 (and L3, etc) page tables.  */
#define ADDR_SPACE_BITS 64

#define P_L2_BITS 9
#define P_L2_SIZE (1 << P_L2_BITS)

#define P_L2_LEVELS (((ADDR_SPACE_BITS - TARGET_PAGE_BITS - 1) / P_L2_BITS) + 1)

typedef PhysPageEntry Node[P_L2_SIZE];

typedef struct PhysPageMap {
    struct rcu_head rcu;

    unsigned sections_nb;
    unsigned sections_nb_alloc;
    unsigned nodes_nb;
    unsigned nodes_nb_alloc;
    Node *nodes;
    MemoryRegionSection *sections;
} PhysPageMap;

struct AddressSpaceDispatch {
    struct rcu_head rcu;

    MemoryRegionSection *mru_section;
    /* This is a multi-level map on the physical address space.
     * The bottom level has pointers to MemoryRegionSections.
     */
    PhysPageEntry phys_map;
    PhysPageMap map;
    AddressSpace *as;
};

#define SUBPAGE_IDX(addr) ((addr) & ~TARGET_PAGE_MASK)
typedef struct subpage_t {
    MemoryRegion iomem;
    AddressSpace *as;
    hwaddr base;
    uint16_t sub_section[];
} subpage_t;

#define PHYS_SECTION_UNASSIGNED 0
#define PHYS_SECTION_NOTDIRTY 1
#define PHYS_SECTION_ROM 2
#define PHYS_SECTION_WATCH 3

static void io_mem_init(void);
static void memory_map_init(void);
static void tcg_commit(MemoryListener *listener);

static MemoryRegion io_mem_watch;

/**
 * CPUAddressSpace: all the information a CPU needs about an AddressSpace
 * @cpu: the CPU whose AddressSpace this is
 * @as: the AddressSpace itself
 * @memory_dispatch: its dispatch pointer (cached, RCU protected)
 * @tcg_as_listener: listener for tracking changes to the AddressSpace
 */
struct CPUAddressSpace {
    CPUState *cpu;
    AddressSpace *as;
    struct AddressSpaceDispatch *memory_dispatch;
    MemoryListener tcg_as_listener;
};

#endif

#if !defined(CONFIG_USER_ONLY)

static void phys_map_node_reserve(PhysPageMap *map, unsigned nodes)
{
    static unsigned alloc_hint = 16;
    if (map->nodes_nb + nodes > map->nodes_nb_alloc) {
        map->nodes_nb_alloc = MAX(map->nodes_nb_alloc, alloc_hint);
        map->nodes_nb_alloc = MAX(map->nodes_nb_alloc, map->nodes_nb + nodes);
        map->nodes = g_renew(Node, map->nodes, map->nodes_nb_alloc);
        alloc_hint = map->nodes_nb_alloc;
    }
}

static uint32_t phys_map_node_alloc(PhysPageMap *map, bool leaf)
{
    unsigned i;
    uint32_t ret;
    PhysPageEntry e;
    PhysPageEntry *p;

    ret = map->nodes_nb++;
    p = map->nodes[ret];
    assert(ret != PHYS_MAP_NODE_NIL);
    assert(ret != map->nodes_nb_alloc);

    e.skip = leaf ? 0 : 1;
    e.ptr = leaf ? PHYS_SECTION_UNASSIGNED : PHYS_MAP_NODE_NIL;
    for (i = 0; i < P_L2_SIZE; ++i) {
        memcpy(&p[i], &e, sizeof(e));
    }
    return ret;
}

static void phys_page_set_level(PhysPageMap *map, PhysPageEntry *lp,
                                hwaddr *index, hwaddr *nb, uint16_t leaf,
                                int level)
{
    PhysPageEntry *p;
    hwaddr step = (hwaddr)1 << (level * P_L2_BITS);

    if (lp->skip && lp->ptr == PHYS_MAP_NODE_NIL) {
        lp->ptr = phys_map_node_alloc(map, level == 0);
    }
    p = map->nodes[lp->ptr];
    lp = &p[(*index >> (level * P_L2_BITS)) & (P_L2_SIZE - 1)];

    while (*nb && lp < &p[P_L2_SIZE]) {
        if ((*index & (step - 1)) == 0 && *nb >= step) {
            lp->skip = 0;
            lp->ptr = leaf;
            *index += step;
            *nb -= step;
        } else {
            phys_page_set_level(map, lp, index, nb, leaf, level - 1);
        }
        ++lp;
    }
}

static void phys_page_set(AddressSpaceDispatch *d,
                          hwaddr index, hwaddr nb,
                          uint16_t leaf)
{
    /* Wildly overreserve - it doesn't matter much. */
    phys_map_node_reserve(&d->map, 3 * P_L2_LEVELS);

    phys_page_set_level(&d->map, &d->phys_map, &index, &nb, leaf, P_L2_LEVELS - 1);
}

/* Compact a non leaf page entry. Simply detect that the entry has a single child,
 * and update our entry so we can skip it and go directly to the destination.
 */
static void phys_page_compact(PhysPageEntry *lp, Node *nodes)
{
    unsigned valid_ptr = P_L2_SIZE;
    int valid = 0;
    PhysPageEntry *p;
    int i;

    if (lp->ptr == PHYS_MAP_NODE_NIL) {
        return;
    }

    p = nodes[lp->ptr];
    for (i = 0; i < P_L2_SIZE; i++) {
        if (p[i].ptr == PHYS_MAP_NODE_NIL) {
            continue;
        }

        valid_ptr = i;
        valid++;
        if (p[i].skip) {
            phys_page_compact(&p[i], nodes);
        }
    }

    /* We can only compress if there's only one child. */
    if (valid != 1) {
        return;
    }

    assert(valid_ptr < P_L2_SIZE);

    /* Don't compress if it won't fit in the # of bits we have. */
    if (lp->skip + p[valid_ptr].skip >= (1 << 3)) {
        return;
    }

    lp->ptr = p[valid_ptr].ptr;
    if (!p[valid_ptr].skip) {
        /* If our only child is a leaf, make this a leaf. */
        /* By design, we should have made this node a leaf to begin with so we
         * should never reach here.
         * But since it's so simple to handle this, let's do it just in case we
         * change this rule.
         */
        lp->skip = 0;
    } else {
        lp->skip += p[valid_ptr].skip;
    }
}

static void phys_page_compact_all(AddressSpaceDispatch *d, int nodes_nb)
{
    if (d->phys_map.skip) {
        phys_page_compact(&d->phys_map, d->map.nodes);
    }
}

static inline bool section_covers_addr(const MemoryRegionSection *section,
                                       hwaddr addr)
{
    /* Memory topology clips a memory region to [0, 2^64); size.hi > 0 means
     * the section must cover the entire address space.
     */
    return int128_gethi(section->size) ||
           range_covers_byte(section->offset_within_address_space,
                             int128_getlo(section->size), addr);
}

static MemoryRegionSection *phys_page_find(PhysPageEntry lp, hwaddr addr,
                                           Node *nodes, MemoryRegionSection *sections)
{
    PhysPageEntry *p;
    hwaddr index = addr >> TARGET_PAGE_BITS;
    int i;

    for (i = P_L2_LEVELS; lp.skip && (i -= lp.skip) >= 0;) {
        if (lp.ptr == PHYS_MAP_NODE_NIL) {
            return &sections[PHYS_SECTION_UNASSIGNED];
        }
        p = nodes[lp.ptr];
        lp = p[(index >> (i * P_L2_BITS)) & (P_L2_SIZE - 1)];
    }

    if (section_covers_addr(&sections[lp.ptr], addr)) {
        return &sections[lp.ptr];
    } else {
        return &sections[PHYS_SECTION_UNASSIGNED];
    }
}

bool memory_region_is_unassigned(MemoryRegion *mr)
{
    return mr != &io_mem_rom && mr != &io_mem_notdirty && !mr->rom_device
        && mr != &io_mem_watch;
}

/* Called from RCU critical section */
static MemoryRegionSection *address_space_lookup_region(AddressSpaceDispatch *d,
                                                        hwaddr addr,
                                                        bool resolve_subpage)
{
    MemoryRegionSection *section = atomic_read(&d->mru_section);
    subpage_t *subpage;
    bool update;

    if (section && section != &d->map.sections[PHYS_SECTION_UNASSIGNED] &&
        section_covers_addr(section, addr)) {
        update = false;
    } else {
        section = phys_page_find(d->phys_map, addr, d->map.nodes,
                                 d->map.sections);
        update = true;
    }
    if (resolve_subpage && section->mr->subpage) {
        subpage = container_of(section->mr, subpage_t, iomem);
        section = &d->map.sections[subpage->sub_section[SUBPAGE_IDX(addr)]];
    }
    if (update) {
        atomic_set(&d->mru_section, section);
    }
    return section;
}

/* Called from RCU critical section */
static MemoryRegionSection *
address_space_translate_internal(AddressSpaceDispatch *d, hwaddr addr, hwaddr *xlat,
                                 hwaddr *plen, bool resolve_subpage)
{
    MemoryRegionSection *section;
    MemoryRegion *mr;
    Int128 diff;

    section = address_space_lookup_region(d, addr, resolve_subpage);
    /* Compute offset within MemoryRegionSection */
    addr -= section->offset_within_address_space;

    /* Compute offset within MemoryRegion */
    *xlat = addr + section->offset_within_region;

    mr = section->mr;

    /* MMIO registers can be expected to perform full-width accesses based only
     * on their address, without considering adjacent registers that could
     * decode to completely different MemoryRegions.  When such registers
     * exist (e.g. I/O ports 0xcf8 and 0xcf9 on most PC chipsets), MMIO
     * regions overlap wildly.  For this reason we cannot clamp the accesses
     * here.
     *
     * If the length is small (as is the case for address_space_ldl/stl),
     * everything works fine.  If the incoming length is large, however,
     * the caller really has to do the clamping through memory_access_size.
     */
    if (memory_region_is_ram(mr)) {
        diff = int128_sub(section->size, int128_make64(addr));
        *plen = int128_get64(int128_min(diff, int128_make64(*plen)));
    }
    return section;
}

/* Called from RCU critical section */
IOMMUTLBEntry address_space_get_iotlb_entry(AddressSpace *as, hwaddr addr,
                                            bool is_write)
{
    IOMMUTLBEntry iotlb = {0};
    MemoryRegionSection *section;
    MemoryRegion *mr;

    for (;;) {
        AddressSpaceDispatch *d = atomic_rcu_read(&as->dispatch);
        section = address_space_lookup_region(d, addr, false);
        addr = addr - section->offset_within_address_space
               + section->offset_within_region;
        mr = section->mr;

        if (!mr->iommu_ops) {
            break;
        }

        iotlb = mr->iommu_ops->translate(mr, addr, is_write);
        if (!(iotlb.perm & (1 << is_write))) {
            iotlb.target_as = NULL;
            break;
        }

        addr = ((iotlb.translated_addr & ~iotlb.addr_mask)
                | (addr & iotlb.addr_mask));
        as = iotlb.target_as;
    }

    return iotlb;
}

/* Called from RCU critical section */
MemoryRegion *address_space_translate(AddressSpace *as, hwaddr addr,
                                      hwaddr *xlat, hwaddr *plen,
                                      bool is_write)
{
    IOMMUTLBEntry iotlb;
    MemoryRegionSection *section;
    MemoryRegion *mr;

    for (;;) {
        AddressSpaceDispatch *d = atomic_rcu_read(&as->dispatch);
        section = address_space_translate_internal(d, addr, &addr, plen, true);
        mr = section->mr;

        if (!mr->iommu_ops) {
            break;
        }

        iotlb = mr->iommu_ops->translate(mr, addr, is_write);
        addr = ((iotlb.translated_addr & ~iotlb.addr_mask)
                | (addr & iotlb.addr_mask));
        *plen = MIN(*plen, (addr | iotlb.addr_mask) - addr + 1);
        if (!(iotlb.perm & (1 << is_write))) {
            mr = &io_mem_unassigned;
            break;
        }

        as = iotlb.target_as;
    }

    if (xen_enabled() && memory_access_is_direct(mr, is_write)) {
        hwaddr page = ((addr & TARGET_PAGE_MASK) + TARGET_PAGE_SIZE) - addr;
        *plen = MIN(page, *plen);
    }

    *xlat = addr;
    return mr;
}

/* Called from RCU critical section */
MemoryRegionSection *
address_space_translate_for_iotlb(CPUState *cpu, int asidx, hwaddr addr,
                                  hwaddr *xlat, hwaddr *plen)
{
    MemoryRegionSection *section;
    AddressSpaceDispatch *d = atomic_rcu_read(&cpu->cpu_ases[asidx].memory_dispatch);

    section = address_space_translate_internal(d, addr, xlat, plen, false);

    assert(!section->mr->iommu_ops);
    return section;
}
#endif

#if !defined(CONFIG_USER_ONLY)

static int cpu_common_post_load(void *opaque, int version_id)
{
    CPUState *cpu = opaque;

    /* 0x01 was CPU_INTERRUPT_EXIT. This line can be removed when the
       version_id is increased. */
    cpu->interrupt_request &= ~0x01;
    tlb_flush(cpu);

    return 0;
}

static int cpu_common_pre_load(void *opaque)
{
    CPUState *cpu = opaque;

    cpu->exception_index = -1;

    return 0;
}

static bool cpu_common_exception_index_needed(void *opaque)
{
    CPUState *cpu = opaque;

    return tcg_enabled() && cpu->exception_index != -1;
}

static const VMStateDescription vmstate_cpu_common_exception_index = {
    .name = "cpu_common/exception_index",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = cpu_common_exception_index_needed,
    .fields = (VMStateField[]) {
        VMSTATE_INT32(exception_index, CPUState),
        VMSTATE_END_OF_LIST()
    }
};

static bool cpu_common_crash_occurred_needed(void *opaque)
{
    CPUState *cpu = opaque;

    return cpu->crash_occurred;
}

static const VMStateDescription vmstate_cpu_common_crash_occurred = {
    .name = "cpu_common/crash_occurred",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = cpu_common_crash_occurred_needed,
    .fields = (VMStateField[]) {
        VMSTATE_BOOL(crash_occurred, CPUState),
        VMSTATE_END_OF_LIST()
    }
};

const VMStateDescription vmstate_cpu_common = {
    .name = "cpu_common",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_load = cpu_common_pre_load,
    .post_load = cpu_common_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(halted, CPUState),
        VMSTATE_UINT32(interrupt_request, CPUState),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription*[]) {
        &vmstate_cpu_common_exception_index,
        &vmstate_cpu_common_crash_occurred,
        NULL
    }
};

#endif

CPUState *qemu_get_cpu(int index)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        if (cpu->cpu_index == index) {
            return cpu;
        }
    }

    return NULL;
}

#if !defined(CONFIG_USER_ONLY)

MemoryListener rr_listener;

static RR_mem_type rr_mem_region_type(MemoryRegion* mr) {
    RR_mem_type mtype = RR_MEM_UNKNOWN;
    if (!(memory_region_is_ram(mr) || memory_region_is_romd(mr))) {
        mtype = RR_MEM_IO;
    } else if (memory_region_is_ram(mr)) {
        mtype = RR_MEM_RAM;
    }
    return mtype;
}

static void rr_mem_region_added_cb(MemoryListener *listener, MemoryRegionSection *section) {
    if (!rr_in_record()) return;
    RR_mem_type mtype = rr_mem_region_type(section->mr);

    rr_mem_region_change_record(section->offset_within_address_space, int128_get64(section->size),
                                section->mr->name, mtype, true);
}

static void rr_mem_region_deleted_cb(MemoryListener *listener, MemoryRegionSection *section) {
    if (!rr_in_record()) return;
    RR_mem_type mtype = rr_mem_region_type(section->mr);
    rr_mem_region_change_record(section->offset_within_address_space, int128_get64(section->size),
                                section->mr->name, mtype, false);
}

void cpu_address_space_init(CPUState *cpu, AddressSpace *as, int asidx)
{
    CPUAddressSpace *newas;

    /* Target code should have set num_ases before calling us */
    assert(asidx < cpu->num_ases);

    if (asidx == 0) {
        /* address space 0 gets the convenience alias */
        cpu->as = as;
    }

    /* KVM cannot currently support multiple address spaces. */
    assert(asidx == 0 || !kvm_enabled());

    if (!cpu->cpu_ases) {
        cpu->cpu_ases = g_new0(CPUAddressSpace, cpu->num_ases);
    }

    newas = &cpu->cpu_ases[asidx];
    newas->cpu = cpu;
    newas->as = as;
    if (tcg_enabled()) {
        newas->tcg_as_listener.commit = tcg_commit;
        memory_listener_register(&newas->tcg_as_listener, as);

        // PANDA Record and Replay
        rr_listener.region_add = rr_mem_region_added_cb;
        rr_listener.region_del = rr_mem_region_deleted_cb;
        memory_listener_register(&rr_listener, as);
    }
}

AddressSpace *cpu_get_address_space(CPUState *cpu, int asidx)
{
    /* Return the AddressSpace corresponding to the specified index */
    return cpu->cpu_ases[asidx].as;
}
#endif

void cpu_exec_unrealizefn(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    cpu_list_remove(cpu);

    if (cc->vmsd != NULL) {
        vmstate_unregister(NULL, cc->vmsd, cpu);
    }
    if (qdev_get_vmsd(DEVICE(cpu)) == NULL) {
        vmstate_unregister(NULL, &vmstate_cpu_common, cpu);
    }
}

void cpu_exec_initfn(CPUState *cpu)
{
    cpu->as = NULL;
    cpu->num_ases = 0;

#ifndef CONFIG_USER_ONLY
    cpu->thread_id = qemu_get_thread_id();

    /* This is a softmmu CPU object, so create a property for it
     * so users can wire up its memory. (This can't go in qom/cpu.c
     * because that file is compiled only once for both user-mode
     * and system builds.) The default if no link is set up is to use
     * the system address space.
     */
    object_property_add_link(OBJECT(cpu), "memory", TYPE_MEMORY_REGION,
                             (Object **)&cpu->memory,
                             qdev_prop_allow_set_link_before_realize,
                             OBJ_PROP_LINK_UNREF_ON_RELEASE,
                             &error_abort);
    cpu->memory = system_memory;
    object_ref(OBJECT(cpu->memory));
#endif
}

void cpu_exec_realizefn(CPUState *cpu, Error **errp)
{
    CPUClass *cc ATTRIBUTE_UNUSED = CPU_GET_CLASS(cpu);

    cpu_list_add(cpu);

#ifndef CONFIG_USER_ONLY
    if (qdev_get_vmsd(DEVICE(cpu)) == NULL) {
        vmstate_register(NULL, cpu->cpu_index, &vmstate_cpu_common, cpu);
    }
    if (cc->vmsd != NULL) {
        vmstate_register(NULL, cpu->cpu_index, cc->vmsd, cpu);
    }
#endif
}

static void breakpoint_invalidate(CPUState *cpu, target_ulong pc)
{
    /* Flush the whole TB as this will not have race conditions
     * even if we don't have proper locking yet.
     * Ideally we would just invalidate the TBs for the
     * specified PC.
     */
    tb_flush(cpu);
}

#if defined(CONFIG_USER_ONLY)
void cpu_watchpoint_remove_all(CPUState *cpu, int mask)

{
}

int cpu_watchpoint_remove(CPUState *cpu, vaddr addr, vaddr len,
                          int flags)
{
    return -ENOSYS;
}

void cpu_watchpoint_remove_by_ref(CPUState *cpu, CPUWatchpoint *watchpoint)
{
}

int cpu_watchpoint_insert(CPUState *cpu, vaddr addr, vaddr len,
                          int flags, CPUWatchpoint **watchpoint)
{
    return -ENOSYS;
}
#else


/* Add a watchpoint.  */
int cpu_watchpoint_insert(CPUState *cpu, vaddr addr, vaddr len,
                          int flags, CPUWatchpoint **watchpoint)
{
    CPUWatchpoint *wp;

    /* forbid ranges which are empty or run off the end of the address space */
    if (len == 0 || (addr + len - 1) < addr) {
        error_report("tried to set invalid watchpoint at %"
                     VADDR_PRIx ", len=%" VADDR_PRIu, addr, len);
        return -EINVAL;
    }
    wp = g_malloc(sizeof(*wp));

    wp->virtaddr = addr;
    wp->len = len;
    wp->flags = flags;

    /* keep all GDB-injected watchpoints in front */
    if (flags & BP_GDB) {
        QTAILQ_INSERT_HEAD(&cpu->watchpoints, wp, entry);
    } else {
        QTAILQ_INSERT_TAIL(&cpu->watchpoints, wp, entry);
    }

    tlb_flush_page(cpu, addr);

    if (watchpoint)
        *watchpoint = wp;
    return 0;
}

/* Remove a specific watchpoint.  */
int cpu_watchpoint_remove(CPUState *cpu, vaddr addr, vaddr len,
                          int flags)
{
    CPUWatchpoint *wp;

    QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
        if (addr == wp->virtaddr && len == wp->len
                && flags == (wp->flags & ~BP_WATCHPOINT_HIT)) {
            cpu_watchpoint_remove_by_ref(cpu, wp);
            return 0;
        }
    }
    return -ENOENT;
}

/* Remove a specific watchpoint by reference.  */
void cpu_watchpoint_remove_by_ref(CPUState *cpu, CPUWatchpoint *watchpoint)
{
    QTAILQ_REMOVE(&cpu->watchpoints, watchpoint, entry);

    tlb_flush_page(cpu, watchpoint->virtaddr);

    g_free(watchpoint);
}

/* Remove all matching watchpoints.  */
void cpu_watchpoint_remove_all(CPUState *cpu, int mask)
{
    CPUWatchpoint *wp, *next;

    QTAILQ_FOREACH_SAFE(wp, &cpu->watchpoints, entry, next) {
        if (wp->flags & mask) {
            cpu_watchpoint_remove_by_ref(cpu, wp);
        }
    }
}

/* Return true if this watchpoint address matches the specified
 * access (ie the address range covered by the watchpoint overlaps
 * partially or completely with the address range covered by the
 * access).
 */
static inline bool cpu_watchpoint_address_matches(CPUWatchpoint *wp,
                                                  vaddr addr,
                                                  vaddr len)
{
    /* We know the lengths are non-zero, but a little caution is
     * required to avoid errors in the case where the range ends
     * exactly at the top of the address space and so addr + len
     * wraps round to zero.
     */
    vaddr wpend = wp->virtaddr + wp->len - 1;
    vaddr addrend = addr + len - 1;

    return !(addr > wpend || wp->virtaddr > addrend);
}

#endif

/* Add a breakpoint.  */
int cpu_breakpoint_insert(CPUState *cpu, vaddr pc, int flags,
                          CPUBreakpoint **breakpoint)
{
    CPUBreakpoint *bp;

    bp = g_malloc(sizeof(*bp));

    bp->pc = pc;
    bp->rr_instr_count = 0;
    bp->flags = flags;

    /* keep all GDB-injected breakpoints in front */
    if (flags & BP_GDB) {
        QTAILQ_INSERT_HEAD(&cpu->breakpoints, bp, entry);
    } else {
        QTAILQ_INSERT_TAIL(&cpu->breakpoints, bp, entry);
    }

    breakpoint_invalidate(cpu, pc);

    if (breakpoint) {
        *breakpoint = bp;
    }
    return 0;
}

int cpu_rr_breakpoint_insert(CPUState *cpu, uint64_t rr_instr_count, int flags,
                          CPUBreakpoint **breakpoint)
{
    CPUBreakpoint *bp;

    bp = g_malloc(sizeof(*bp));

    bp->pc = 0;
    bp->rr_instr_count = rr_instr_count;
    bp->flags = flags;

    /* keep all GDB-injected breakpoints in front */
    if (flags & BP_GDB) {
        QTAILQ_INSERT_HEAD(&cpu->breakpoints, bp, entry);
    } else {
        QTAILQ_INSERT_TAIL(&cpu->breakpoints, bp, entry);
    }

    //breakpoint_invalidate(cpu, pc);
    tb_flush(cpu);
    
    printf("Inserted bp @ instr count %lu\n", rr_instr_count);

    if (breakpoint) {
        *breakpoint = bp;
    }
    return 0;
}

/* Remove a specific breakpoint.  */
int cpu_breakpoint_remove(CPUState *cpu, vaddr pc, int flags)
{
    CPUBreakpoint *bp;

    QTAILQ_FOREACH(bp, &cpu->breakpoints, entry) {
        if (bp->pc == pc && bp->flags == flags) {
            cpu_breakpoint_remove_by_ref(cpu, bp);
            return 0;
        }
    }
    return -ENOENT;
}

/* Remove a specific breakpoint by rr instr count.  */
int cpu_breakpoint_remove_by_instr(CPUState *cpu, uint64_t rr_instr_count, int flags)
{
    CPUBreakpoint *bp;

    QTAILQ_FOREACH(bp, &cpu->breakpoints, entry) {
        if (bp->rr_instr_count == rr_instr_count && bp->flags == flags) {
            cpu_breakpoint_remove_by_ref(cpu, bp);
            return 0;
        }
    }
    return -ENOENT;
}

/* Remove a specific breakpoint by reference.  */
void cpu_breakpoint_remove_by_ref(CPUState *cpu, CPUBreakpoint *breakpoint)
{
    QTAILQ_REMOVE(&cpu->breakpoints, breakpoint, entry);

    //breakpoint_invalidate(cpu, breakpoint->pc);

    g_free(breakpoint);
}

/* Remove all matching breakpoints. */
void cpu_breakpoint_remove_all(CPUState *cpu, int mask)
{
    CPUBreakpoint *bp, *next;

    QTAILQ_FOREACH_SAFE(bp, &cpu->breakpoints, entry, next) {
        if (bp->flags & mask) {
            cpu_breakpoint_remove_by_ref(cpu, bp);
        }
    }
}

/*
 * rw: Handles reverse-continue logic. Checks whether we are in first or second pass
 * and whether we've finished scanning an entire checkpoint
 */
void cpu_rcont_check_restore(CPUState* cpu, uint64_t rr_instr_count){
    
    if (unlikely(cpu->reverse_flags & GDB_RCONT)) {
        // If we've reached the end of this checkpoint region
        if (rr_instr_count >= cpu->last_gdb_instr-1) {
             int closest_num;
             if ((closest_num = get_closest_checkpoint_num(cpu->last_gdb_instr-1)) < 0) {
                fprintf(stderr, "get_closest_checkpoint_num %d\n", closest_num); 
                abort();
             }

            if (cpu->last_bp_hit_instr == 0) {
                // let's restart from the previous checkpoint

                 if (closest_num == 1) {
                    // No more checkpoints before this one! Insert bp at beginning
                    cpu_rr_breakpoint_insert(cpu, 1, BP_GDB, NULL);
                    cpu->reverse_flags = 0;
                    panda_restore_by_num(1);
                 }

                 Checkpoint* prev_checkpoint;
                 if ((prev_checkpoint = get_checkpoint(closest_num-1)) == NULL) {
                     fprintf(stderr, "gen_intmed_code: get_checkpoint fail\n");
                     abort();
                 }

                 cpu->last_gdb_instr = get_checkpoint(closest_num)->guest_instr_count;
                 tb_flush(cpu);
                 tlb_flush(cpu);
                 panda_restore(prev_checkpoint);
            } else {
                // Re-run from checkpoint to latest breakpoint!
                cpu->reverse_flags = GDB_RCONT_BREAK;
                panda_restore_by_num(closest_num);
            }
        }
    }
}

/* enable or disable single step mode. EXCP_DEBUG is returned by the
   CPU loop after each instruction */
void cpu_single_step(CPUState *cpu, int enabled)
{
    if (cpu->singlestep_enabled != enabled) {
        cpu->singlestep_enabled = enabled;
        if (kvm_enabled()) {
            kvm_update_guest_debug(cpu, 0);
        } else {
            /* must flush all the translated code to avoid inconsistencies */
            /* XXX: only flush what is necessary */
            tb_flush(cpu);
        }
    }
}

void cpu_abort(CPUState *cpu, const char *fmt, ...)
{
    va_list ap;
    va_list ap2;

    va_start(ap, fmt);
    va_copy(ap2, ap);
    fprintf(stderr, "qemu: fatal: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    cpu_dump_state(cpu, stderr, fprintf, CPU_DUMP_FPU | CPU_DUMP_CCOP);
    if (qemu_log_separate()) {
        qemu_log_lock();
        qemu_log("qemu: fatal: ");
        qemu_log_vprintf(fmt, ap2);
        qemu_log("\n");
        log_cpu_state(cpu, CPU_DUMP_FPU | CPU_DUMP_CCOP);
        qemu_log_flush();
        qemu_log_unlock();
        qemu_log_close();
    }
    va_end(ap2);
    va_end(ap);
    replay_finish();
#if defined(CONFIG_USER_ONLY)
    {
        struct sigaction act;
        sigfillset(&act.sa_mask);
        act.sa_handler = SIG_DFL;
        sigaction(SIGABRT, &act, NULL);
    }
#endif
    abort();
}

#if !defined(CONFIG_USER_ONLY)
/* Called from RCU critical section */
static RAMBlock *qemu_get_ram_block(ram_addr_t addr)
{
    RAMBlock *block;

    block = atomic_rcu_read(&ram_list.mru_block);
    if (block && addr - block->offset < block->max_length) {
        return block;
    }
    QLIST_FOREACH_RCU(block, &ram_list.blocks, next) {
        if (addr - block->offset < block->max_length) {
            goto found;
        }
    }

    fprintf(stderr, "Bad ram offset %" PRIx64 "\n", (uint64_t)addr);
    abort();

found:
    /* It is safe to write mru_block outside the iothread lock.  This
     * is what happens:
     *
     *     mru_block = xxx
     *     rcu_read_unlock()
     *                                        xxx removed from list
     *                  rcu_read_lock()
     *                  read mru_block
     *                                        mru_block = NULL;
     *                                        call_rcu(reclaim_ramblock, xxx);
     *                  rcu_read_unlock()
     *
     * atomic_rcu_set is not needed here.  The block was already published
     * when it was placed into the list.  Here we're just making an extra
     * copy of the pointer.
     */
    ram_list.mru_block = block;
    return block;
}

static void tlb_reset_dirty_range_all(ram_addr_t start, ram_addr_t length)
{
    CPUState *cpu;
    ram_addr_t start1;
    RAMBlock *block;
    ram_addr_t end;

    end = TARGET_PAGE_ALIGN(start + length);
    start &= TARGET_PAGE_MASK;

    rcu_read_lock();
    block = qemu_get_ram_block(start);
    assert(block == qemu_get_ram_block(end - 1));
    start1 = (uintptr_t)ramblock_ptr(block, start - block->offset);
    CPU_FOREACH(cpu) {
        tlb_reset_dirty(cpu, start1, length);
    }
    rcu_read_unlock();
}

/* Note: start and end must be within the same ram block.  */
bool cpu_physical_memory_test_and_clear_dirty(ram_addr_t start,
                                              ram_addr_t length,
                                              unsigned client)
{
    DirtyMemoryBlocks *blocks;
    unsigned long end, page;
    bool dirty = false;

    if (length == 0) {
        return false;
    }

    end = TARGET_PAGE_ALIGN(start + length) >> TARGET_PAGE_BITS;
    page = start >> TARGET_PAGE_BITS;

    rcu_read_lock();

    blocks = atomic_rcu_read(&ram_list.dirty_memory[client]);

    while (page < end) {
        unsigned long idx = page / DIRTY_MEMORY_BLOCK_SIZE;
        unsigned long offset = page % DIRTY_MEMORY_BLOCK_SIZE;
        unsigned long num = MIN(end - page, DIRTY_MEMORY_BLOCK_SIZE - offset);

        dirty |= bitmap_test_and_clear_atomic(blocks->blocks[idx],
                                              offset, num);
        page += num;
    }

    rcu_read_unlock();

    if (dirty && tcg_enabled()) {
        tlb_reset_dirty_range_all(start, length);
    }

    return dirty;
}

/* Called from RCU critical section */
hwaddr memory_region_section_get_iotlb(CPUState *cpu,
                                       MemoryRegionSection *section,
                                       target_ulong vaddr,
                                       hwaddr paddr, hwaddr xlat,
                                       int prot,
                                       target_ulong *address)
{
    hwaddr iotlb;
    CPUWatchpoint *wp;

    if (memory_region_is_ram(section->mr)) {
        /* Normal RAM.  */
        iotlb = memory_region_get_ram_addr(section->mr) + xlat;
        if (!section->readonly) {
            iotlb |= PHYS_SECTION_NOTDIRTY;
        } else {
            iotlb |= PHYS_SECTION_ROM;
        }
    } else {
        AddressSpaceDispatch *d;

        d = atomic_rcu_read(&section->address_space->dispatch);
        iotlb = section - d->map.sections;
        iotlb += xlat;
    }

    /* Make accesses to pages with watchpoints go via the
       watchpoint trap routines.  */
    QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
        if (cpu_watchpoint_address_matches(wp, vaddr, TARGET_PAGE_SIZE)) {
            /* Avoid trapping reads of pages with a write breakpoint. */
            if ((prot & PAGE_WRITE) || (wp->flags & BP_MEM_READ)) {
                iotlb = PHYS_SECTION_WATCH + paddr;
                *address |= TLB_MMIO;
                break;
            }
        }
    }

    return iotlb;
}
#endif /* defined(CONFIG_USER_ONLY) */

#if !defined(CONFIG_USER_ONLY)

static int subpage_register (subpage_t *mmio, uint32_t start, uint32_t end,
                             uint16_t section);
static subpage_t *subpage_init(AddressSpace *as, hwaddr base);

static void *(*phys_mem_alloc)(size_t size, uint64_t *align) =
                               qemu_anon_ram_alloc;

/*
 * Set a custom physical guest memory alloator.
 * Accelerators with unusual needs may need this.  Hopefully, we can
 * get rid of it eventually.
 */
void phys_mem_set_alloc(void *(*alloc)(size_t, uint64_t *align))
{
    phys_mem_alloc = alloc;
}

static uint16_t phys_section_add(PhysPageMap *map,
                                 MemoryRegionSection *section)
{
    /* The physical section number is ORed with a page-aligned
     * pointer to produce the iotlb entries.  Thus it should
     * never overflow into the page-aligned value.
     */
    assert(map->sections_nb < TARGET_PAGE_SIZE);

    if (map->sections_nb == map->sections_nb_alloc) {
        map->sections_nb_alloc = MAX(map->sections_nb_alloc * 2, 16);
        map->sections = g_renew(MemoryRegionSection, map->sections,
                                map->sections_nb_alloc);
    }
    map->sections[map->sections_nb] = *section;
    memory_region_ref(section->mr);
    return map->sections_nb++;
}

static void phys_section_destroy(MemoryRegion *mr)
{
    bool have_sub_page = mr->subpage;

    memory_region_unref(mr);

    if (have_sub_page) {
        subpage_t *subpage = container_of(mr, subpage_t, iomem);
        object_unref(OBJECT(&subpage->iomem));
        g_free(subpage);
    }
}

static void phys_sections_free(PhysPageMap *map)
{
    while (map->sections_nb > 0) {
        MemoryRegionSection *section = &map->sections[--map->sections_nb];
        phys_section_destroy(section->mr);
    }
    g_free(map->sections);
    g_free(map->nodes);
}

static void register_subpage(AddressSpaceDispatch *d, MemoryRegionSection *section)
{
    subpage_t *subpage;
    hwaddr base = section->offset_within_address_space
        & TARGET_PAGE_MASK;
    MemoryRegionSection *existing = phys_page_find(d->phys_map, base,
                                                   d->map.nodes, d->map.sections);
    MemoryRegionSection subsection = {
        .offset_within_address_space = base,
        .size = int128_make64(TARGET_PAGE_SIZE),
    };
    hwaddr start, end;

    assert(existing->mr->subpage || existing->mr == &io_mem_unassigned);

    if (!(existing->mr->subpage)) {
        subpage = subpage_init(d->as, base);
        subsection.address_space = d->as;
        subsection.mr = &subpage->iomem;
        phys_page_set(d, base >> TARGET_PAGE_BITS, 1,
                      phys_section_add(&d->map, &subsection));
    } else {
        subpage = container_of(existing->mr, subpage_t, iomem);
    }
    start = section->offset_within_address_space & ~TARGET_PAGE_MASK;
    end = start + int128_get64(section->size) - 1;
    subpage_register(subpage, start, end,
                     phys_section_add(&d->map, section));
}


static void register_multipage(AddressSpaceDispatch *d,
                               MemoryRegionSection *section)
{
    hwaddr start_addr = section->offset_within_address_space;
    uint16_t section_index = phys_section_add(&d->map, section);
    uint64_t num_pages = int128_get64(int128_rshift(section->size,
                                                    TARGET_PAGE_BITS));

    assert(num_pages);
    phys_page_set(d, start_addr >> TARGET_PAGE_BITS, num_pages, section_index);
}

static void mem_add(MemoryListener *listener, MemoryRegionSection *section)
{
    AddressSpace *as = container_of(listener, AddressSpace, dispatch_listener);
    AddressSpaceDispatch *d = as->next_dispatch;
    MemoryRegionSection now = *section, remain = *section;
    Int128 page_size = int128_make64(TARGET_PAGE_SIZE);

    if (now.offset_within_address_space & ~TARGET_PAGE_MASK) {
        uint64_t left = TARGET_PAGE_ALIGN(now.offset_within_address_space)
                       - now.offset_within_address_space;

        now.size = int128_min(int128_make64(left), now.size);
        register_subpage(d, &now);
    } else {
        now.size = int128_zero();
    }
    while (int128_ne(remain.size, now.size)) {
        remain.size = int128_sub(remain.size, now.size);
        remain.offset_within_address_space += int128_get64(now.size);
        remain.offset_within_region += int128_get64(now.size);
        now = remain;
        if (int128_lt(remain.size, page_size)) {
            register_subpage(d, &now);
        } else if (remain.offset_within_address_space & ~TARGET_PAGE_MASK) {
            now.size = page_size;
            register_subpage(d, &now);
        } else {
            now.size = int128_and(now.size, int128_neg(page_size));
            register_multipage(d, &now);
        }
    }
}

void qemu_flush_coalesced_mmio_buffer(void)
{
    if (kvm_enabled())
        kvm_flush_coalesced_mmio_buffer();
}

void qemu_mutex_lock_ramlist(void)
{
    qemu_mutex_lock(&ram_list.mutex);
}

void qemu_mutex_unlock_ramlist(void)
{
    qemu_mutex_unlock(&ram_list.mutex);
}

#ifdef __linux__
/*
 * FIXME TOCTTOU: this iterates over memory backends' mem-path, which
 * may or may not name the same files / on the same filesystem now as
 * when we actually open and map them.  Iterate over the file
 * descriptors instead, and use qemu_fd_getpagesize().
 */
static int find_max_supported_pagesize(Object *obj, void *opaque)
{
    char *mem_path;
    long *hpsize_min = opaque;

    if (object_dynamic_cast(obj, TYPE_MEMORY_BACKEND)) {
        mem_path = object_property_get_str(obj, "mem-path", NULL);
        if (mem_path) {
            long hpsize = qemu_mempath_getpagesize(mem_path);
            if (hpsize < *hpsize_min) {
                *hpsize_min = hpsize;
            }
        } else {
            *hpsize_min = getpagesize();
        }
    }

    return 0;
}

long qemu_getrampagesize(void)
{
    long hpsize = LONG_MAX;
    long mainrampagesize;
    Object *memdev_root;

    if (mem_path) {
        mainrampagesize = qemu_mempath_getpagesize(mem_path);
    } else {
        mainrampagesize = getpagesize();
    }

    /* it's possible we have memory-backend objects with
     * hugepage-backed RAM. these may get mapped into system
     * address space via -numa parameters or memory hotplug
     * hooks. we want to take these into account, but we
     * also want to make sure these supported hugepage
     * sizes are applicable across the entire range of memory
     * we may boot from, so we take the min across all
     * backends, and assume normal pages in cases where a
     * backend isn't backed by hugepages.
     */
    memdev_root = object_resolve_path("/objects", NULL);
    if (memdev_root) {
        object_child_foreach(memdev_root, find_max_supported_pagesize, &hpsize);
    }
    if (hpsize == LONG_MAX) {
        /* No additional memory regions found ==> Report main RAM page size */
        return mainrampagesize;
    }

    /* If NUMA is disabled or the NUMA nodes are not backed with a
     * memory-backend, then there is at least one node using "normal" RAM,
     * so if its page size is smaller we have got to report that size instead.
     */
    if (hpsize > mainrampagesize &&
        (nb_numa_nodes == 0 || numa_info[0].node_memdev == NULL)) {
        static bool warned;
        if (!warned) {
            error_report("Huge page support disabled (n/a for main memory).");
            warned = true;
        }
        return mainrampagesize;
    }

    return hpsize;
}
#else
long qemu_getrampagesize(void)
{
    return getpagesize();
}
#endif

#ifdef __linux__
static int64_t get_file_size(int fd)
{
    int64_t size = lseek(fd, 0, SEEK_END);
    if (size < 0) {
        return -errno;
    }
    return size;
}

static void *file_ram_alloc(RAMBlock *block,
                            ram_addr_t memory,
                            const char *path,
                            Error **errp)
{
    bool unlink_on_error = false;
    char *filename;
    char *sanitized_name;
    char *c;
    void *area = MAP_FAILED;
    int fd = -1;
    int64_t file_size;

    if (kvm_enabled() && !kvm_has_sync_mmu()) {
        error_setg(errp,
                   "host lacks kvm mmu notifiers, -mem-path unsupported");
        return NULL;
    }

    for (;;) {
        fd = open(path, O_RDWR);
        if (fd >= 0) {
            /* @path names an existing file, use it */
            break;
        }
        if (errno == ENOENT) {
            /* @path names a file that doesn't exist, create it */
            fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0644);
            if (fd >= 0) {
                unlink_on_error = true;
                break;
            }
        } else if (errno == EISDIR) {
            /* @path names a directory, create a file there */
            /* Make name safe to use with mkstemp by replacing '/' with '_'. */
            sanitized_name = g_strdup(memory_region_name(block->mr));
            for (c = sanitized_name; *c != '\0'; c++) {
                if (*c == '/') {
                    *c = '_';
                }
            }

            filename = g_strdup_printf("%s/qemu_back_mem.%s.XXXXXX", path,
                                       sanitized_name);
            g_free(sanitized_name);

            fd = mkstemp(filename);
            if (fd >= 0) {
                unlink(filename);
                g_free(filename);
                break;
            }
            g_free(filename);
        }
        if (errno != EEXIST && errno != EINTR) {
            error_setg_errno(errp, errno,
                             "can't open backing store %s for guest RAM",
                             path);
            goto error;
        }
        /*
         * Try again on EINTR and EEXIST.  The latter happens when
         * something else creates the file between our two open().
         */
    }

    block->page_size = qemu_fd_getpagesize(fd);
    block->mr->align = block->page_size;
#if defined(__s390x__)
    if (kvm_enabled()) {
        block->mr->align = MAX(block->mr->align, QEMU_VMALLOC_ALIGN);
    }
#endif

    file_size = get_file_size(fd);

    if (memory < block->page_size) {
        error_setg(errp, "memory size 0x" RAM_ADDR_FMT " must be equal to "
                   "or larger than page size 0x%zx",
                   memory, block->page_size);
        goto error;
    }

    if (file_size > 0 && file_size < memory) {
        error_setg(errp, "backing store %s size 0x%" PRIx64
                   " does not match 'size' option 0x" RAM_ADDR_FMT,
                   path, file_size, memory);
        goto error;
    }

    memory = ROUND_UP(memory, block->page_size);

    /*
     * ftruncate is not supported by hugetlbfs in older
     * hosts, so don't bother bailing out on errors.
     * If anything goes wrong with it under other filesystems,
     * mmap will fail.
     *
     * Do not truncate the non-empty backend file to avoid corrupting
     * the existing data in the file. Disabling shrinking is not
     * enough. For example, the current vNVDIMM implementation stores
     * the guest NVDIMM labels at the end of the backend file. If the
     * backend file is later extended, QEMU will not be able to find
     * those labels. Therefore, extending the non-empty backend file
     * is disabled as well.
     */
    if (!file_size && ftruncate(fd, memory)) {
        perror("ftruncate");
    }

    area = qemu_ram_mmap(fd, memory, block->mr->align,
                         block->flags & RAM_SHARED);
    if (area == MAP_FAILED) {
        error_setg_errno(errp, errno,
                         "unable to map backing store for guest RAM");
        goto error;
    }

    if (mem_prealloc) {
        os_mem_prealloc(fd, area, memory, smp_cpus, errp);
        if (errp && *errp) {
            goto error;
        }
    }

    block->fd = fd;
    return area;

error:
    if (area != MAP_FAILED) {
        qemu_ram_munmap(area, memory);
    }
    if (unlink_on_error) {
        unlink(path);
    }
    if (fd != -1) {
        close(fd);
    }
    return NULL;
}
#endif

/* Called with the ramlist lock held.  */
static ram_addr_t find_ram_offset(ram_addr_t size)
{
    RAMBlock *block, *next_block;
    ram_addr_t offset = RAM_ADDR_MAX, mingap = RAM_ADDR_MAX;

    assert(size != 0); /* it would hand out same offset multiple times */

    if (QLIST_EMPTY_RCU(&ram_list.blocks)) {
        return 0;
    }

    QLIST_FOREACH_RCU(block, &ram_list.blocks, next) {
        ram_addr_t end, next = RAM_ADDR_MAX;

        end = block->offset + block->max_length;

        QLIST_FOREACH_RCU(next_block, &ram_list.blocks, next) {
            if (next_block->offset >= end) {
                next = MIN(next, next_block->offset);
            }
        }
        if (next - end >= size && next - end < mingap) {
            offset = end;
            mingap = next - end;
        }
    }

    if (offset == RAM_ADDR_MAX) {
        fprintf(stderr, "Failed to find gap of requested size: %" PRIu64 "\n",
                (uint64_t)size);
        abort();
    }

    return offset;
}

ram_addr_t last_ram_offset(void)
{
    RAMBlock *block;
    ram_addr_t last = 0;

    rcu_read_lock();
    QLIST_FOREACH_RCU(block, &ram_list.blocks, next) {
        last = MAX(last, block->offset + block->max_length);
    }
    rcu_read_unlock();
    return last;
}

static void qemu_ram_setup_dump(void *addr, ram_addr_t size)
{
    int ret;

    /* Use MADV_DONTDUMP, if user doesn't want the guest memory in the core */
    if (!machine_dump_guest_core(current_machine)) {
        ret = qemu_madvise(addr, size, QEMU_MADV_DONTDUMP);
        if (ret) {
            perror("qemu_madvise");
            fprintf(stderr, "madvise doesn't support MADV_DONTDUMP, "
                            "but dump_guest_core=off specified\n");
        }
    }
}

const char *qemu_ram_get_idstr(RAMBlock *rb)
{
    return rb->idstr;
}

/* Called with iothread lock held.  */
void qemu_ram_set_idstr(RAMBlock *new_block, const char *name, DeviceState *dev)
{
    RAMBlock *block;

    assert(new_block);
    assert(!new_block->idstr[0]);

    if (dev) {
        char *id = qdev_get_dev_path(dev);
        if (id) {
            snprintf(new_block->idstr, sizeof(new_block->idstr), "%s/", id);
            g_free(id);
        }
    }
    pstrcat(new_block->idstr, sizeof(new_block->idstr), name);

    rcu_read_lock();
    QLIST_FOREACH_RCU(block, &ram_list.blocks, next) {
        if (block != new_block &&
            !strcmp(block->idstr, new_block->idstr)) {
            fprintf(stderr, "RAMBlock \"%s\" already registered, abort!\n",
                    new_block->idstr);
            abort();
        }
    }
    rcu_read_unlock();
}

/* Called with iothread lock held.  */
void qemu_ram_unset_idstr(RAMBlock *block)
{
    /* FIXME: arch_init.c assumes that this is not called throughout
     * migration.  Ignore the problem since hot-unplug during migration
     * does not work anyway.
     */
    if (block) {
        memset(block->idstr, 0, sizeof(block->idstr));
    }
}

size_t qemu_ram_pagesize(RAMBlock *rb)
{
    return rb->page_size;
}

/* Returns the largest size of page in use */
size_t qemu_ram_pagesize_largest(void)
{
    RAMBlock *block;
    size_t largest = 0;

    QLIST_FOREACH_RCU(block, &ram_list.blocks, next) {
        largest = MAX(largest, qemu_ram_pagesize(block));
    }

    return largest;
}

static int memory_try_enable_merging(void *addr, size_t len)
{
    if (!machine_mem_merge(current_machine)) {
        /* disabled by the user */
        return 0;
    }

    return qemu_madvise(addr, len, QEMU_MADV_MERGEABLE);
}

/* Only legal before guest might have detected the memory size: e.g. on
 * incoming migration, or right after reset.
 *
 * As memory core doesn't know how is memory accessed, it is up to
 * resize callback to update device state and/or add assertions to detect
 * misuse, if necessary.
 */
int qemu_ram_resize(RAMBlock *block, ram_addr_t newsize, Error **errp)
{
    assert(block);

    newsize = HOST_PAGE_ALIGN(newsize);

    if (block->used_length == newsize) {
        return 0;
    }

    if (!(block->flags & RAM_RESIZEABLE)) {
        error_setg_errno(errp, EINVAL,
                         "Length mismatch: %s: 0x" RAM_ADDR_FMT
                         " in != 0x" RAM_ADDR_FMT, block->idstr,
                         newsize, block->used_length);
        return -EINVAL;
    }

    if (block->max_length < newsize) {
        error_setg_errno(errp, EINVAL,
                         "Length too large: %s: 0x" RAM_ADDR_FMT
                         " > 0x" RAM_ADDR_FMT, block->idstr,
                         newsize, block->max_length);
        return -EINVAL;
    }

    cpu_physical_memory_clear_dirty_range(block->offset, block->used_length);
    block->used_length = newsize;
    cpu_physical_memory_set_dirty_range(block->offset, block->used_length,
                                        DIRTY_CLIENTS_ALL);
    memory_region_set_size(block->mr, newsize);
    if (block->resized) {
        block->resized(block->idstr, newsize, block->host);
    }
    return 0;
}

/* Called with ram_list.mutex held */
static void dirty_memory_extend(ram_addr_t old_ram_size,
                                ram_addr_t new_ram_size)
{
    ram_addr_t old_num_blocks = DIV_ROUND_UP(old_ram_size,
                                             DIRTY_MEMORY_BLOCK_SIZE);
    ram_addr_t new_num_blocks = DIV_ROUND_UP(new_ram_size,
                                             DIRTY_MEMORY_BLOCK_SIZE);
    int i;

    /* Only need to extend if block count increased */
    if (new_num_blocks <= old_num_blocks) {
        return;
    }

    for (i = 0; i < DIRTY_MEMORY_NUM; i++) {
        DirtyMemoryBlocks *old_blocks;
        DirtyMemoryBlocks *new_blocks;
        int j;

        old_blocks = atomic_rcu_read(&ram_list.dirty_memory[i]);
        new_blocks = g_malloc(sizeof(*new_blocks) +
                              sizeof(new_blocks->blocks[0]) * new_num_blocks);

        if (old_num_blocks) {
            memcpy(new_blocks->blocks, old_blocks->blocks,
                   old_num_blocks * sizeof(old_blocks->blocks[0]));
        }

        for (j = old_num_blocks; j < new_num_blocks; j++) {
            new_blocks->blocks[j] = bitmap_new(DIRTY_MEMORY_BLOCK_SIZE);
        }

        atomic_rcu_set(&ram_list.dirty_memory[i], new_blocks);

        if (old_blocks) {
            g_free_rcu(old_blocks, rcu);
        }
    }
}

static void ram_block_add(RAMBlock *new_block, Error **errp)
{
    RAMBlock *block;
    RAMBlock *last_block = NULL;
    ram_addr_t old_ram_size, new_ram_size;
    Error *err = NULL;

    old_ram_size = last_ram_offset() >> TARGET_PAGE_BITS;

    qemu_mutex_lock_ramlist();
    new_block->offset = find_ram_offset(new_block->max_length);

    if (!new_block->host) {
        if (xen_enabled()) {
            xen_ram_alloc(new_block->offset, new_block->max_length,
                          new_block->mr, &err);
            if (err) {
                error_propagate(errp, err);
                qemu_mutex_unlock_ramlist();
                return;
            }
        } else {
            new_block->host = phys_mem_alloc(new_block->max_length,
                                             &new_block->mr->align);
            if (!new_block->host) {
                error_setg_errno(errp, errno,
                                 "cannot set up guest memory '%s'",
                                 memory_region_name(new_block->mr));
                qemu_mutex_unlock_ramlist();
                return;
            }
            memory_try_enable_merging(new_block->host, new_block->max_length);
        }
    }

    new_ram_size = MAX(old_ram_size,
              (new_block->offset + new_block->max_length) >> TARGET_PAGE_BITS);
    if (new_ram_size > old_ram_size) {
        migration_bitmap_extend(old_ram_size, new_ram_size);
        dirty_memory_extend(old_ram_size, new_ram_size);
    }
    /* Keep the list sorted from biggest to smallest block.  Unlike QTAILQ,
     * QLIST (which has an RCU-friendly variant) does not have insertion at
     * tail, so save the last element in last_block.
     */
    QLIST_FOREACH_RCU(block, &ram_list.blocks, next) {
        last_block = block;
        if (block->max_length < new_block->max_length) {
            break;
        }
    }
    if (block) {
        QLIST_INSERT_BEFORE_RCU(block, new_block, next);
    } else if (last_block) {
        QLIST_INSERT_AFTER_RCU(last_block, new_block, next);
    } else { /* list is empty */
        QLIST_INSERT_HEAD_RCU(&ram_list.blocks, new_block, next);
    }
    ram_list.mru_block = NULL;

    /* Write list before version */
    smp_wmb();
    ram_list.version++;
    qemu_mutex_unlock_ramlist();

    cpu_physical_memory_set_dirty_range(new_block->offset,
                                        new_block->used_length,
                                        DIRTY_CLIENTS_ALL);

    if (new_block->host) {
        qemu_ram_setup_dump(new_block->host, new_block->max_length);
        qemu_madvise(new_block->host, new_block->max_length, QEMU_MADV_HUGEPAGE);
        /* MADV_DONTFORK is also needed by KVM in absence of synchronous MMU */
        qemu_madvise(new_block->host, new_block->max_length, QEMU_MADV_DONTFORK);
        ram_block_notify_add(new_block->host, new_block->max_length);
    }
}

#ifdef __linux__
RAMBlock *qemu_ram_alloc_from_file(ram_addr_t size, MemoryRegion *mr,
                                   bool share, const char *mem_path,
                                   Error **errp)
{
    RAMBlock *new_block;
    Error *local_err = NULL;

    if (xen_enabled()) {
        error_setg(errp, "-mem-path not supported with Xen");
        return NULL;
    }

    if (phys_mem_alloc != qemu_anon_ram_alloc) {
        /*
         * file_ram_alloc() needs to allocate just like
         * phys_mem_alloc, but we haven't bothered to provide
         * a hook there.
         */
        error_setg(errp,
                   "-mem-path not supported with this accelerator");
        return NULL;
    }

    size = HOST_PAGE_ALIGN(size);
    new_block = g_malloc0(sizeof(*new_block));
    new_block->mr = mr;
    new_block->used_length = size;
    new_block->max_length = size;
    new_block->flags = share ? RAM_SHARED : 0;
    new_block->host = file_ram_alloc(new_block, size,
                                     mem_path, errp);
    if (!new_block->host) {
        g_free(new_block);
        return NULL;
    }

    ram_block_add(new_block, &local_err);
    if (local_err) {
        g_free(new_block);
        error_propagate(errp, local_err);
        return NULL;
    }
    return new_block;
}
#endif

static
RAMBlock *qemu_ram_alloc_internal(ram_addr_t size, ram_addr_t max_size,
                                  void (*resized)(const char*,
                                                  uint64_t length,
                                                  void *host),
                                  void *host, bool resizeable,
                                  MemoryRegion *mr, Error **errp)
{
    RAMBlock *new_block;
    Error *local_err = NULL;

    size = HOST_PAGE_ALIGN(size);
    max_size = HOST_PAGE_ALIGN(max_size);
    new_block = g_malloc0(sizeof(*new_block));
    new_block->mr = mr;
    new_block->resized = resized;
    new_block->used_length = size;
    new_block->max_length = max_size;
    assert(max_size >= size);
    new_block->fd = -1;
    new_block->page_size = getpagesize();
    new_block->host = host;
    if (host) {
        new_block->flags |= RAM_PREALLOC;
    }
    if (resizeable) {
        new_block->flags |= RAM_RESIZEABLE;
    }
    ram_block_add(new_block, &local_err);
    if (local_err) {
        g_free(new_block);
        error_propagate(errp, local_err);
        return NULL;
    }
    return new_block;
}

RAMBlock *qemu_ram_alloc_from_ptr(ram_addr_t size, void *host,
                                   MemoryRegion *mr, Error **errp)
{
    return qemu_ram_alloc_internal(size, size, NULL, host, false, mr, errp);
}

RAMBlock *qemu_ram_alloc(ram_addr_t size, MemoryRegion *mr, Error **errp)
{
    return qemu_ram_alloc_internal(size, size, NULL, NULL, false, mr, errp);
}

RAMBlock *qemu_ram_alloc_resizeable(ram_addr_t size, ram_addr_t maxsz,
                                     void (*resized)(const char*,
                                                     uint64_t length,
                                                     void *host),
                                     MemoryRegion *mr, Error **errp)
{
    return qemu_ram_alloc_internal(size, maxsz, resized, NULL, true, mr, errp);
}

static void reclaim_ramblock(RAMBlock *block)
{
    if (block->flags & RAM_PREALLOC) {
        ;
    } else if (xen_enabled()) {
        xen_invalidate_map_cache_entry(block->host);
#ifndef _WIN32
    } else if (block->fd >= 0) {
        qemu_ram_munmap(block->host, block->max_length);
        close(block->fd);
#endif
    } else {
        qemu_anon_ram_free(block->host, block->max_length);
    }
    g_free(block);
}

void qemu_ram_free(RAMBlock *block)
{
    if (!block) {
        return;
    }

    if (block->host) {
        ram_block_notify_remove(block->host, block->max_length);
    }

    qemu_mutex_lock_ramlist();
    QLIST_REMOVE_RCU(block, next);
    ram_list.mru_block = NULL;
    /* Write list before version */
    smp_wmb();
    ram_list.version++;
    call_rcu(block, reclaim_ramblock, rcu);
    qemu_mutex_unlock_ramlist();
}

#ifndef _WIN32
void qemu_ram_remap(ram_addr_t addr, ram_addr_t length)
{
    RAMBlock *block;
    ram_addr_t offset;
    int flags;
    void *area, *vaddr;

    QLIST_FOREACH_RCU(block, &ram_list.blocks, next) {
        offset = addr - block->offset;
        if (offset < block->max_length) {
            vaddr = ramblock_ptr(block, offset);
            if (block->flags & RAM_PREALLOC) {
                ;
            } else if (xen_enabled()) {
                abort();
            } else {
                flags = MAP_FIXED;
                if (block->fd >= 0) {
                    flags |= (block->flags & RAM_SHARED ?
                              MAP_SHARED : MAP_PRIVATE);
                    area = mmap(vaddr, length, PROT_READ | PROT_WRITE,
                                flags, block->fd, offset);
                } else {
                    /*
                     * Remap needs to match alloc.  Accelerators that
                     * set phys_mem_alloc never remap.  If they did,
                     * we'd need a remap hook here.
                     */
                    assert(phys_mem_alloc == qemu_anon_ram_alloc);

                    flags |= MAP_PRIVATE | MAP_ANONYMOUS;
                    area = mmap(vaddr, length, PROT_READ | PROT_WRITE,
                                flags, -1, 0);
                }
                if (area != vaddr) {
                    fprintf(stderr, "Could not remap addr: "
                            RAM_ADDR_FMT "@" RAM_ADDR_FMT "\n",
                            length, addr);
                    exit(1);
                }
                memory_try_enable_merging(vaddr, length);
                qemu_ram_setup_dump(vaddr, length);
            }
        }
    }
}
#endif /* !_WIN32 */

/* Return a host pointer to ram allocated with qemu_ram_alloc.
 * This should not be used for general purpose DMA.  Use address_space_map
 * or address_space_rw instead. For local memory (e.g. video ram) that the
 * device owns, use memory_region_get_ram_ptr.
 *
 * Called within RCU critical section.
 */
void *qemu_map_ram_ptr(RAMBlock *ram_block, ram_addr_t addr)
{
    RAMBlock *block = ram_block;

    if (block == NULL) {
        block = qemu_get_ram_block(addr);
        addr -= block->offset;
    }

    if (xen_enabled() && block->host == NULL) {
        /* We need to check if the requested address is in the RAM
         * because we don't want to map the entire memory in QEMU.
         * In that case just map until the end of the page.
         */
        if (block->offset == 0) {
            return xen_map_cache(addr, 0, 0);
        }

        block->host = xen_map_cache(block->offset, block->max_length, 1);
    }
    return ramblock_ptr(block, addr);
}

/* Return a host pointer to guest's ram. Similar to qemu_map_ram_ptr
 * but takes a size argument.
 *
 * Called within RCU critical section.
 */
static void *qemu_ram_ptr_length(RAMBlock *ram_block, ram_addr_t addr,
                                 hwaddr *size)
{
    RAMBlock *block = ram_block;
    if (*size == 0) {
        return NULL;
    }

    if (block == NULL) {
        block = qemu_get_ram_block(addr);
        addr -= block->offset;
    }
    *size = MIN(*size, block->max_length - addr);

    if (xen_enabled() && block->host == NULL) {
        /* We need to check if the requested address is in the RAM
         * because we don't want to map the entire memory in QEMU.
         * In that case just map the requested area.
         */
        if (block->offset == 0) {
            return xen_map_cache(addr, *size, 1);
        }

        block->host = xen_map_cache(block->offset, block->max_length, 1);
    }

    return ramblock_ptr(block, addr);
}

/*
 * Translates a host ptr back to a RAMBlock, a ram_addr and an offset
 * in that RAMBlock.
 *
 * ptr: Host pointer to look up
 * round_offset: If true round the result offset down to a page boundary
 * *ram_addr: set to result ram_addr
 * *offset: set to result offset within the RAMBlock
 *
 * Returns: RAMBlock (or NULL if not found)
 *
 * By the time this function returns, the returned pointer is not protected
 * by RCU anymore.  If the caller is not within an RCU critical section and
 * does not hold the iothread lock, it must have other means of protecting the
 * pointer, such as a reference to the region that includes the incoming
 * ram_addr_t.
 */
RAMBlock *qemu_ram_block_from_host(void *ptr, bool round_offset,
                                   ram_addr_t *offset)
{
    RAMBlock *block;
    uint8_t *host = ptr;

    if (xen_enabled()) {
        ram_addr_t ram_addr;
        rcu_read_lock();
        ram_addr = xen_ram_addr_from_mapcache(ptr);
        block = qemu_get_ram_block(ram_addr);
        if (block) {
            *offset = ram_addr - block->offset;
        }
        rcu_read_unlock();
        return block;
    }

    rcu_read_lock();
    block = atomic_rcu_read(&ram_list.mru_block);
    if (block && block->host && host - block->host < block->max_length) {
        goto found;
    }

    QLIST_FOREACH_RCU(block, &ram_list.blocks, next) {
        /* This case append when the block is not mapped. */
        if (block->host == NULL) {
            continue;
        }
        if (host - block->host < block->max_length) {
            goto found;
        }
    }

    rcu_read_unlock();
    return NULL;

found:
    *offset = (host - block->host);
    if (round_offset) {
        *offset &= TARGET_PAGE_MASK;
    }
    rcu_read_unlock();
    return block;
}

/*
 * Finds the named RAMBlock
 *
 * name: The name of RAMBlock to find
 *
 * Returns: RAMBlock (or NULL if not found)
 */
RAMBlock *qemu_ram_block_by_name(const char *name)
{
    RAMBlock *block;

    QLIST_FOREACH_RCU(block, &ram_list.blocks, next) {
        if (!strcmp(name, block->idstr)) {
            return block;
        }
    }

    return NULL;
}

/* Some of the softmmu routines need to translate from a host pointer
   (typically a TLB entry) back to a ram offset.  */
ram_addr_t qemu_ram_addr_from_host(void *ptr)
{
    RAMBlock *block;
    ram_addr_t offset;

    block = qemu_ram_block_from_host(ptr, false, &offset);
    if (!block) {
        return RAM_ADDR_INVALID;
    }

    return block->offset + offset;
}

/* Called within RCU critical section.  */
static void notdirty_mem_write(void *opaque, hwaddr ram_addr,
                               uint64_t val, unsigned size)
{
    bool locked = false;

    if (!cpu_physical_memory_get_dirty_flag(ram_addr, DIRTY_MEMORY_CODE)) {
        locked = true;
        tb_lock();
        tb_invalidate_phys_page_fast(ram_addr, size);
    }
    switch (size) {
    case 1:
        stb_p(qemu_map_ram_ptr(NULL, ram_addr), val);
        break;
    case 2:
        stw_p(qemu_map_ram_ptr(NULL, ram_addr), val);
        break;
    case 4:
        stl_p(qemu_map_ram_ptr(NULL, ram_addr), val);
        break;
    default:
        abort();
    }

    if (locked) {
        tb_unlock();
    }

    /* Set both VGA and migration bits for simplicity and to remove
     * the notdirty callback faster.
     */
    cpu_physical_memory_set_dirty_range(ram_addr, size,
                                        DIRTY_CLIENTS_NOCODE);
    /* we remove the notdirty callback only if the code has been
       flushed */
    if (!cpu_physical_memory_is_clean(ram_addr)) {
        tlb_set_dirty(current_cpu, current_cpu->mem_io_vaddr);
    }
}

static bool notdirty_mem_accepts(void *opaque, hwaddr addr,
                                 unsigned size, bool is_write)
{
    return is_write;
}

static const MemoryRegionOps notdirty_mem_ops = {
    .write = notdirty_mem_write,
    .valid.accepts = notdirty_mem_accepts,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

/* Generate a debug exception if a watchpoint has been hit.  */
static void check_watchpoint(int offset, int len, MemTxAttrs attrs, int flags)
{
    CPUState *cpu = current_cpu;
    CPUClass *cc = CPU_GET_CLASS(cpu);
    CPUArchState *env = cpu->env_ptr;
    target_ulong pc, cs_base;
    target_ulong vaddr;
    CPUWatchpoint *wp;
    uint32_t cpu_flags;

    uint64_t rr_instr_count = rr_get_guest_instr_count();

    // If we disabled watchpoints in gdbstub for a step or continue, reenable
    if (cpu->watchpoints_disabled){
        cpu->watchpoints_disabled = false;
        return;
    }

    // Handle reverse-continue action and possibly restore checkpoint
    cpu_rcont_check_restore(cpu, rr_instr_count);

    if (cpu->watchpoint_hit) {
        /* We re-entered the check after replacing the TB. Now raise
         * the debug interrupt so that is will trigger after the
         * current instruction. */
        cpu_interrupt(cpu, CPU_INTERRUPT_DEBUG);
        return;
    }

    vaddr = (cpu->mem_io_vaddr & TARGET_PAGE_MASK) + offset;
    vaddr = cc->adjust_watchpoint_address(cpu, vaddr, len);
    
    QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
        if (cpu_watchpoint_address_matches(wp, vaddr, len)
            && (wp->flags & flags)) {
            if (flags == BP_MEM_READ) {
                wp->flags |= BP_WATCHPOINT_HIT_READ;
            } else {
                wp->flags |= BP_WATCHPOINT_HIT_WRITE;
            }
            wp->hitaddr = vaddr;
            wp->hitattrs = attrs;

            if (unlikely(cpu->reverse_flags & GDB_RCONT)) {
                // first pass of reverse-continue
                // skip this watchpoint and record it
                cpu->last_bp_hit_instr = rr_instr_count;
                return;
            }  else if (cpu->reverse_flags & GDB_RCONT_BREAK) {
                // We are doing second pass of reverse-continue
                // break on latest breakpoint/watchpoint 
                if (rr_instr_count > cpu->last_bp_hit_instr) {
                    fprintf(stderr, "GDB_RCONT_BREAK went too far");
                    abort();
                }

                if  (!(rr_instr_count == cpu->last_bp_hit_instr)) {
                    // if we're reverse-continuing to a certain point, ignore all other bps except the last one
                    return;
                }
            }

            if (!cpu->watchpoint_hit) {
                if (wp->flags & BP_CPU &&
                    !cc->debug_check_watchpoint(cpu, wp)) {
                    wp->flags &= ~BP_WATCHPOINT_HIT;
                    continue;
                }
                cpu->watchpoint_hit = wp;

                /* The tb_lock will be reset when cpu_loop_exit or
                 * cpu_loop_exit_noexc longjmp back into the cpu_exec
                 * main loop.
                 */
                tb_lock();
                tb_check_watchpoint(cpu);

                // We're done with reverse-continue, clear the flag
                cpu->reverse_flags = 0;

                // rw: Let's just break before access if we're in RR replay
                if (wp->flags & BP_STOP_BEFORE_ACCESS || rr_in_replay()) {
                    cpu->exception_index = EXCP_DEBUG;
                    cpu->rr_guest_instr_count -= 1;
                    cpu_loop_exit(cpu);
                } else {
                    cpu_get_tb_cpu_state(env, &pc, &cs_base, &cpu_flags);
                    tb_gen_code(cpu, pc, cs_base, cpu_flags, 1);
                    cpu_loop_exit_noexc(cpu);
                }
            }
        } else {
            wp->flags &= ~BP_WATCHPOINT_HIT;
        }
    }
}

/* Watchpoint access routines.  Watchpoints are inserted using TLB tricks,
   so these check for a hit then pass through to the normal out-of-line
   phys routines.  */
static MemTxResult watch_mem_read(void *opaque, hwaddr addr, uint64_t *pdata,
                                  unsigned size, MemTxAttrs attrs)
{
    MemTxResult res;
    uint64_t data;
    int asidx = cpu_asidx_from_attrs(current_cpu, attrs);
    AddressSpace *as = current_cpu->cpu_ases[asidx].as;

    check_watchpoint(addr & ~TARGET_PAGE_MASK, size, attrs, BP_MEM_READ);
    switch (size) {
    case 1:
        data = address_space_ldub(as, addr, attrs, &res);
        break;
    case 2:
        data = address_space_lduw(as, addr, attrs, &res);
        break;
    case 4:
        data = address_space_ldl(as, addr, attrs, &res);
        break;
    default: abort();
    }
    *pdata = data;
    return res;
}

static MemTxResult watch_mem_write(void *opaque, hwaddr addr,
                                   uint64_t val, unsigned size,
                                   MemTxAttrs attrs)
{
    MemTxResult res;
    int asidx = cpu_asidx_from_attrs(current_cpu, attrs);
    AddressSpace *as = current_cpu->cpu_ases[asidx].as;

    check_watchpoint(addr & ~TARGET_PAGE_MASK, size, attrs, BP_MEM_WRITE);
    switch (size) {
    case 1:
        address_space_stb(as, addr, val, attrs, &res);
        break;
    case 2:
        address_space_stw(as, addr, val, attrs, &res);
        break;
    case 4:
        address_space_stl(as, addr, val, attrs, &res);
        break;
    default: abort();
    }
    return res;
}

static const MemoryRegionOps watch_mem_ops = {
    .read_with_attrs = watch_mem_read,
    .write_with_attrs = watch_mem_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static MemTxResult subpage_read(void *opaque, hwaddr addr, uint64_t *data,
                                unsigned len, MemTxAttrs attrs)
{
    subpage_t *subpage = opaque;
    uint8_t buf[8];
    MemTxResult res;

#if defined(DEBUG_SUBPAGE)
    printf("%s: subpage %p len %u addr " TARGET_FMT_plx "\n", __func__,
           subpage, len, addr);
#endif
    res = address_space_read(subpage->as, addr + subpage->base,
                             attrs, buf, len);
    if (res) {
        return res;
    }
    switch (len) {
    case 1:
        *data = ldub_p(buf);
        return MEMTX_OK;
    case 2:
        *data = lduw_p(buf);
        return MEMTX_OK;
    case 4:
        *data = ldl_p(buf);
        return MEMTX_OK;
    case 8:
        *data = ldq_p(buf);
        return MEMTX_OK;
    default:
        abort();
    }
}

static MemTxResult subpage_write(void *opaque, hwaddr addr,
                                 uint64_t value, unsigned len, MemTxAttrs attrs)
{
    subpage_t *subpage = opaque;
    uint8_t buf[8];

#if defined(DEBUG_SUBPAGE)
    printf("%s: subpage %p len %u addr " TARGET_FMT_plx
           " value %"PRIx64"\n",
           __func__, subpage, len, addr, value);
#endif
    switch (len) {
    case 1:
        stb_p(buf, value);
        break;
    case 2:
        stw_p(buf, value);
        break;
    case 4:
        stl_p(buf, value);
        break;
    case 8:
        stq_p(buf, value);
        break;
    default:
        abort();
    }
    return address_space_write(subpage->as, addr + subpage->base,
                               attrs, buf, len);
}

static bool subpage_accepts(void *opaque, hwaddr addr,
                            unsigned len, bool is_write)
{
    subpage_t *subpage = opaque;
#if defined(DEBUG_SUBPAGE)
    printf("%s: subpage %p %c len %u addr " TARGET_FMT_plx "\n",
           __func__, subpage, is_write ? 'w' : 'r', len, addr);
#endif

    return address_space_access_valid(subpage->as, addr + subpage->base,
                                      len, is_write);
}

static const MemoryRegionOps subpage_ops = {
    .read_with_attrs = subpage_read,
    .write_with_attrs = subpage_write,
    .impl.min_access_size = 1,
    .impl.max_access_size = 8,
    .valid.min_access_size = 1,
    .valid.max_access_size = 8,
    .valid.accepts = subpage_accepts,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static int subpage_register (subpage_t *mmio, uint32_t start, uint32_t end,
                             uint16_t section)
{
    int idx, eidx;

    if (start >= TARGET_PAGE_SIZE || end >= TARGET_PAGE_SIZE)
        return -1;
    idx = SUBPAGE_IDX(start);
    eidx = SUBPAGE_IDX(end);
#if defined(DEBUG_SUBPAGE)
    printf("%s: %p start %08x end %08x idx %08x eidx %08x section %d\n",
           __func__, mmio, start, end, idx, eidx, section);
#endif
    for (; idx <= eidx; idx++) {
        mmio->sub_section[idx] = section;
    }

    return 0;
}

static subpage_t *subpage_init(AddressSpace *as, hwaddr base)
{
    subpage_t *mmio;

    mmio = g_malloc0(sizeof(subpage_t) + TARGET_PAGE_SIZE * sizeof(uint16_t));
    mmio->as = as;
    mmio->base = base;
    memory_region_init_io(&mmio->iomem, NULL, &subpage_ops, mmio,
                          NULL, TARGET_PAGE_SIZE);
    mmio->iomem.subpage = true;
#if defined(DEBUG_SUBPAGE)
    printf("%s: %p base " TARGET_FMT_plx " len %08x\n", __func__,
           mmio, base, TARGET_PAGE_SIZE);
#endif
    subpage_register(mmio, 0, TARGET_PAGE_SIZE-1, PHYS_SECTION_UNASSIGNED);

    return mmio;
}

static uint16_t dummy_section(PhysPageMap *map, AddressSpace *as,
                              MemoryRegion *mr)
{
    assert(as);
    MemoryRegionSection section = {
        .address_space = as,
        .mr = mr,
        .offset_within_address_space = 0,
        .offset_within_region = 0,
        .size = int128_2_64(),
    };

    return phys_section_add(map, &section);
}

MemoryRegion *iotlb_to_region(CPUState *cpu, hwaddr index, MemTxAttrs attrs)
{
    int asidx = cpu_asidx_from_attrs(cpu, attrs);
    CPUAddressSpace *cpuas = &cpu->cpu_ases[asidx];
    AddressSpaceDispatch *d = atomic_rcu_read(&cpuas->memory_dispatch);
    MemoryRegionSection *sections = d->map.sections;

    return sections[index & ~TARGET_PAGE_MASK].mr;
}

static void io_mem_init(void)
{
    memory_region_init_io(&io_mem_rom, NULL, &unassigned_mem_ops, NULL, "rom", UINT64_MAX);
    memory_region_init_io(&io_mem_unassigned, NULL, &unassigned_mem_ops, NULL,
                          "unassigned", UINT64_MAX);
    memory_region_init_io(&io_mem_notdirty, NULL, &notdirty_mem_ops, NULL,
                          "notdirty", UINT64_MAX);
    memory_region_init_io(&io_mem_watch, NULL, &watch_mem_ops, NULL,
                          "watch", UINT64_MAX);
}

static void mem_begin(MemoryListener *listener)
{
    AddressSpace *as = container_of(listener, AddressSpace, dispatch_listener);
    AddressSpaceDispatch *d = g_new0(AddressSpaceDispatch, 1);
    uint16_t n;

    n = dummy_section(&d->map, as, &io_mem_unassigned);
    assert(n == PHYS_SECTION_UNASSIGNED);
    n = dummy_section(&d->map, as, &io_mem_notdirty);
    assert(n == PHYS_SECTION_NOTDIRTY);
    n = dummy_section(&d->map, as, &io_mem_rom);
    assert(n == PHYS_SECTION_ROM);
    n = dummy_section(&d->map, as, &io_mem_watch);
    assert(n == PHYS_SECTION_WATCH);

    d->phys_map  = (PhysPageEntry) { .ptr = PHYS_MAP_NODE_NIL, .skip = 1 };
    d->as = as;
    as->next_dispatch = d;
}

static void address_space_dispatch_free(AddressSpaceDispatch *d)
{
    phys_sections_free(&d->map);
    g_free(d);
}

static void mem_commit(MemoryListener *listener)
{
    AddressSpace *as = container_of(listener, AddressSpace, dispatch_listener);
    AddressSpaceDispatch *cur = as->dispatch;
    AddressSpaceDispatch *next = as->next_dispatch;

    phys_page_compact_all(next, next->map.nodes_nb);

    atomic_rcu_set(&as->dispatch, next);
    if (cur) {
        call_rcu(cur, address_space_dispatch_free, rcu);
    }
}

static void tcg_commit(MemoryListener *listener)
{
    CPUAddressSpace *cpuas;
    AddressSpaceDispatch *d;

    /* since each CPU stores ram addresses in its TLB cache, we must
       reset the modified entries */
    cpuas = container_of(listener, CPUAddressSpace, tcg_as_listener);
    cpu_reloading_memory_map();
    /* The CPU and TLB are protected by the iothread lock.
     * We reload the dispatch pointer now because cpu_reloading_memory_map()
     * may have split the RCU critical section.
     */
    d = atomic_rcu_read(&cpuas->as->dispatch);
    atomic_rcu_set(&cpuas->memory_dispatch, d);
    tlb_flush(cpuas->cpu);
}

void address_space_init_dispatch(AddressSpace *as)
{
    as->dispatch = NULL;
    as->dispatch_listener = (MemoryListener) {
        .begin = mem_begin,
        .commit = mem_commit,
        .region_add = mem_add,
        .region_nop = mem_add,
        .priority = 0,
    };
    memory_listener_register(&as->dispatch_listener, as);
}

void address_space_unregister(AddressSpace *as)
{
    memory_listener_unregister(&as->dispatch_listener);
}

void address_space_destroy_dispatch(AddressSpace *as)
{
    AddressSpaceDispatch *d = as->dispatch;

    atomic_rcu_set(&as->dispatch, NULL);
    if (d) {
        call_rcu(d, address_space_dispatch_free, rcu);
    }
}

static void memory_map_init(void)
{
    system_memory = g_malloc(sizeof(*system_memory));

    memory_region_init(system_memory, NULL, "system", UINT64_MAX);
    address_space_init(&address_space_memory, system_memory, "memory");

    system_io = g_malloc(sizeof(*system_io));
    memory_region_init_io(system_io, NULL, &unassigned_io_ops, NULL, "io",
                          65536);
    address_space_init(&address_space_io, system_io, "I/O");
}

MemoryRegion *get_system_memory(void)
{
    return system_memory;
}

MemoryRegion *get_system_io(void)
{
    return system_io;
}

#endif /* !defined(CONFIG_USER_ONLY) */

/* physical memory access (slow version, mainly for debug) */
#if defined(CONFIG_USER_ONLY)
int cpu_memory_rw_debug(CPUState *cpu, target_ulong addr,
                        uint8_t *buf, int len, int is_write)
{
    int l, flags;
    target_ulong page;
    void * p;

    while (len > 0) {
        page = addr & TARGET_PAGE_MASK;
        l = (page + TARGET_PAGE_SIZE) - addr;
        if (l > len)
            l = len;
        flags = page_get_flags(page);
        if (!(flags & PAGE_VALID))
            return -1;
        if (is_write) {
            if (!(flags & PAGE_WRITE))
                return -1;
            /* XXX: this code should not depend on lock_user */
            if (!(p = lock_user(VERIFY_WRITE, addr, l, 0)))
                return -1;
            memcpy(p, buf, l);
            unlock_user(p, addr, l);
        } else {
            if (!(flags & PAGE_READ))
                return -1;
            /* XXX: this code should not depend on lock_user */
            if (!(p = lock_user(VERIFY_READ, addr, l, 1)))
                return -1;
            memcpy(buf, p, l);
            unlock_user(p, addr, 0);
        }
        len -= l;
        buf += l;
        addr += l;
    }
    return 0;
}

#else

static void invalidate_and_set_dirty(MemoryRegion *mr, hwaddr addr,
                                     hwaddr length)
{
    uint8_t dirty_log_mask = memory_region_get_dirty_log_mask(mr);
    addr += memory_region_get_ram_addr(mr);

    /* No early return if dirty_log_mask is or becomes 0, because
     * cpu_physical_memory_set_dirty_range will still call
     * xen_modified_memory.
     */
    if (dirty_log_mask) {
        dirty_log_mask =
            cpu_physical_memory_range_includes_clean(addr, length, dirty_log_mask);
    }
    if (dirty_log_mask & (1 << DIRTY_MEMORY_CODE)) {
        tb_lock();
        tb_invalidate_phys_range(addr, addr + length);
        tb_unlock();
        dirty_log_mask &= ~(1 << DIRTY_MEMORY_CODE);
    }
    cpu_physical_memory_set_dirty_range(addr, length, dirty_log_mask);
}

static int memory_access_size(MemoryRegion *mr, unsigned l, hwaddr addr)
{
    unsigned access_size_max = mr->ops->valid.max_access_size;

    /* Regions are assumed to support 1-4 byte accesses unless
       otherwise specified.  */
    if (access_size_max == 0) {
        access_size_max = 4;
    }

    /* Bound the maximum access by the alignment of the address.  */
    if (!mr->ops->impl.unaligned) {
        unsigned align_size_max = addr & -addr;
        if (align_size_max != 0 && align_size_max < access_size_max) {
            access_size_max = align_size_max;
        }
    }

    /* Don't attempt accesses larger than the maximum.  */
    if (l > access_size_max) {
        l = access_size_max;
    }
    l = pow2floor(l);

    return l;
}

static bool prepare_mmio_access(MemoryRegion *mr)
{
    bool unlocked = !qemu_mutex_iothread_locked();
    bool release_lock = false;

    if (unlocked && mr->global_locking) {
        qemu_mutex_lock_iothread();
        unlocked = false;
        release_lock = true;
    }
    if (mr->flush_coalesced_mmio) {
        if (unlocked) {
            qemu_mutex_lock_iothread();
        }
        qemu_flush_coalesced_mmio_buffer();
        if (unlocked) {
            qemu_mutex_unlock_iothread();
        }
    }

    return release_lock;
}


/* Called within RCU critical section.  */
static MemTxResult address_space_write_continue(AddressSpace *as, hwaddr addr,
                                                MemTxAttrs attrs,
                                                const uint8_t *buf,
                                                int len, hwaddr addr1,
                                                hwaddr l, MemoryRegion *mr)
{
    uint8_t *ptr;
    uint64_t val;
    MemTxResult result = MEMTX_OK;
    bool release_lock = false;

    for (;;) {
        if (!memory_access_is_direct(mr, true)) {
            release_lock |= prepare_mmio_access(mr);
            l = memory_access_size(mr, l, addr1);
            /* XXX: could force current_cpu to NULL to avoid
               potential bugs */
            /* Maybe we want to record the value of result in this switch statement */
            switch (l) {
            case 8:
                /* 64 bit write access */
                val = ldq_p(buf);
                RR_DO_RECORD_OR_REPLAY(
                /*action=*/
                result |= memory_region_dispatch_write(mr, addr1, val, 8,
                                                       attrs),
                /*record=*/RR_NO_ACTION,
                /*replay=*/RR_NO_ACTION,
                /*location=*/RR_CALLSITE_WRITE_8);
                break;
            case 4:
                /* 32 bit write access */
                val = (uint32_t)ldl_p(buf);
                RR_DO_RECORD_OR_REPLAY(
                /*action=*/
                result |= memory_region_dispatch_write(mr, addr1, val, 4,
                                                       attrs),
                /*record=*/RR_NO_ACTION,
                /*replay=*/RR_NO_ACTION,
                /*location=*/RR_CALLSITE_WRITE_4);
                break;
            case 2:
                /* 16 bit write access */
                val = lduw_p(buf);
                RR_DO_RECORD_OR_REPLAY(
                /*action=*/
                result |= memory_region_dispatch_write(mr, addr1, val, 2,
                                                       attrs),
                /*record=*/RR_NO_ACTION,
                /*replay=*/RR_NO_ACTION,
                /*location=*/RR_CALLSITE_WRITE_2);
                break;
            case 1:
                /* 8 bit write access */
                val = ldub_p(buf);
                RR_DO_RECORD_OR_REPLAY(
                /*action=*/
                result |= memory_region_dispatch_write(mr, addr1, val, 1,
                                                       attrs),
                /*record=*/RR_NO_ACTION,
                /*replay=*/RR_NO_ACTION,
                /*location=*/RR_CALLSITE_WRITE_1);
                break;
            default:
                abort();
            }
        } else {
            /* RAM case */
            ptr = qemu_map_ram_ptr(mr->ram_block, addr1);
            if (rr_in_record() && (rr_record_in_progress || rr_record_in_main_loop_wait)) {
                // We should record the memory address relative to the address space, not physical memory.
                // During replay, this address will be translated into the physical address.
                rr_device_mem_rw_call_record(addr, buf, l, /*is_write*/1);
            }
            panda_callbacks_before_dma(first_cpu, addr1, buf, l, /*is_write=1*/ 1);
            memcpy(ptr, buf, l);
            panda_callbacks_after_dma(first_cpu, addr1, buf, l, /*is_write=1*/ 1);
            invalidate_and_set_dirty(mr, addr1, l);
        }

        if (release_lock) {
            qemu_mutex_unlock_iothread();
            release_lock = false;
        }

        len -= l;
        buf += l;
        addr += l;

        if (!len) {
            break;
        }

        l = len;
        mr = address_space_translate(as, addr, &addr1, &l, true);
    }

    return result;
}

MemTxResult address_space_write(AddressSpace *as, hwaddr addr, MemTxAttrs attrs,
                                const uint8_t *buf, int len)
{
    hwaddr l;
    hwaddr addr1;
    MemoryRegion *mr;
    MemTxResult result = MEMTX_OK;

    if (len > 0) {
        rcu_read_lock();
        l = len;
        mr = address_space_translate(as, addr, &addr1, &l, true);
        result = address_space_write_continue(as, addr, attrs, buf, len,
                                              addr1, l, mr);
        rcu_read_unlock();
    }

    return result;
}

/* Called within RCU critical section.  */
MemTxResult address_space_read_continue(AddressSpace *as, hwaddr addr,
                                        MemTxAttrs attrs, uint8_t *buf,
                                        int len, hwaddr addr1, hwaddr l,
                                        MemoryRegion *mr)
{
    uint8_t *ptr;
    uint64_t val;
    MemTxResult result = MEMTX_OK;
    bool release_lock = false;
    _Static_assert(sizeof(MemTxResult) == 4, "Unexpected size of MemTxResult (does not match rr_input_4)");
    for (;;) {
        if (!memory_access_is_direct(mr, false)) {
            /* I/O case */
            release_lock |= prepare_mmio_access(mr);
            l = memory_access_size(mr, l, addr1);
            switch (l) {
            case 8:
                /* 64 bit read access */
                RR_DO_RECORD_OR_REPLAY(
                /*action=*/result |= memory_region_dispatch_read(mr, addr1, &val, 8,
                                                      attrs),
                /*record=*/rr_input_4(&result); rr_input_8(&val),
                /*replay=*/rr_input_4(&result); rr_input_8(&val),
                /*location=*/RR_CALLSITE_READ_8);
                stq_p(buf, val);
                break;
            case 4:
                /* 32 bit read access */
                RR_DO_RECORD_OR_REPLAY(
                /*action=*/result |= memory_region_dispatch_read(mr, addr1, &val, 4,
                                                      attrs),
                /*record=*/rr_input_4(&result); rr_input_8(&val),
                /*replay=*/rr_input_4(&result); rr_input_8(&val),
                /*location=*/RR_CALLSITE_READ_4);
                stl_p(buf, val);
                break;
            case 2:
                /* 16 bit read access */
                RR_DO_RECORD_OR_REPLAY(
                /*action=*/result |= memory_region_dispatch_read(mr, addr1, &val, 2,
                                                      attrs),
                /*record=*/rr_input_4(&result); rr_input_8(&val),
                /*replay=*/rr_input_4(&result); rr_input_8(&val),
                /*location=*/RR_CALLSITE_READ_2);
                stw_p(buf, val);
                break;
            case 1:
                /* 8 bit read access */
                RR_DO_RECORD_OR_REPLAY(
                /*action=*/result |= memory_region_dispatch_read(mr, addr1, &val, 1,
                                                      attrs),
                /*record=*/rr_input_4(&result); rr_input_8(&val),
                /*replay=*/rr_input_4(&result); rr_input_8(&val),
                /*location=*/RR_CALLSITE_READ_1);
                stb_p(buf, val);
                break;
            default:
                abort();
            }
        } else {
            /* RAM case */
            ptr = qemu_map_ram_ptr(mr->ram_block, addr1);
            panda_callbacks_before_dma(first_cpu, addr1, buf, l, /*is_write=1*/ 0);
            memcpy(buf, ptr, l);
            panda_callbacks_after_dma(first_cpu, addr1, buf, l, /*is_write=1*/ 0);
        }

        if (release_lock) {
            qemu_mutex_unlock_iothread();
            release_lock = false;
        }

        len -= l;
        buf += l;
        addr += l;

        if (!len) {
            break;
        }

        l = len;
        mr = address_space_translate(as, addr, &addr1, &l, false);
    }

    return result;
}

MemTxResult address_space_read_full(AddressSpace *as, hwaddr addr,
                                    MemTxAttrs attrs, uint8_t *buf, int len)
{
    hwaddr l;
    hwaddr addr1;
    MemoryRegion *mr;
    MemTxResult result = MEMTX_OK;

    if (len > 0) {
        rcu_read_lock();
        l = len;
        mr = address_space_translate(as, addr, &addr1, &l, false);
        result = address_space_read_continue(as, addr, attrs, buf, len,
                                             addr1, l, mr);
        rcu_read_unlock();
    }

    return result;
}

MemTxResult address_space_rw(AddressSpace *as, hwaddr addr, MemTxAttrs attrs,
                             uint8_t *buf, int len, bool is_write)
{
    if (is_write) {
        return address_space_write(as, addr, attrs, (uint8_t *)buf, len);
    } else {
        return address_space_read(as, addr, attrs, (uint8_t *)buf, len);
    }
}


void cpu_physical_memory_rw(hwaddr addr, uint8_t *buf,
                            int len, int is_write)
{
    address_space_rw(&address_space_memory, addr, MEMTXATTRS_UNSPECIFIED,
                            buf, len, is_write);

}

// if safe == true that means we want this to fail for IO mem
MemTxResult cpu_physical_memory_rw_ex(hwaddr addr, uint8_t *buf,
                                     int len, int is_write, bool safe) {
    hwaddr l = len;
    hwaddr addr1;
    MemoryRegion *mr = address_space_translate(&address_space_memory, addr, &addr1, &l, is_write);
    if (safe && !memory_access_is_direct(mr, is_write)) {
        return MEMTX_ERROR;
    }
    return address_space_rw(&address_space_memory, addr, MEMTXATTRS_UNSPECIFIED,
                            buf, len, is_write);
}


enum write_rom_type {
    WRITE_DATA,
    FLUSH_CACHE,
};

static inline void cpu_physical_memory_write_rom_internal(AddressSpace *as,
    hwaddr addr, const uint8_t *buf, int len, enum write_rom_type type)
{
    hwaddr l;
    uint8_t *ptr;
    hwaddr addr1;
    MemoryRegion *mr;

    rcu_read_lock();
    while (len > 0) {
        l = len;
        mr = address_space_translate(as, addr, &addr1, &l, true);

        if (!(memory_region_is_ram(mr) ||
              memory_region_is_romd(mr))) {
            l = memory_access_size(mr, l, addr1);
        } else {
            /* ROM/RAM case */
            ptr = qemu_map_ram_ptr(mr->ram_block, addr1);
            switch (type) {
            case WRITE_DATA:
                if (rr_in_record() && (rr_record_in_progress || rr_record_in_main_loop_wait)) {
                    rr_device_mem_rw_call_record(addr1, buf, l, 1);
                }
                memcpy(ptr, buf, l);
                invalidate_and_set_dirty(mr, addr1, l);
                break;
            case FLUSH_CACHE:
                flush_icache_range((uintptr_t)ptr, (uintptr_t)ptr + l);
                break;
            }
        }
        len -= l;
        buf += l;
        addr += l;
    }
    rcu_read_unlock();
}

/* used for ROM loading : can write in RAM and ROM */
void cpu_physical_memory_write_rom(AddressSpace *as, hwaddr addr,
                                   const uint8_t *buf, int len)
{
    cpu_physical_memory_write_rom_internal(as, addr, buf, len, WRITE_DATA);
}

void cpu_flush_icache_range(hwaddr start, int len)
{
    /*
     * This function should do the same thing as an icache flush that was
     * triggered from within the guest. For TCG we are always cache coherent,
     * so there is no need to flush anything. For KVM / Xen we need to flush
     * the host's instruction cache at least.
     */
    if (tcg_enabled()) {
        return;
    }

    cpu_physical_memory_write_rom_internal(&address_space_memory,
                                           start, NULL, len, FLUSH_CACHE);
}

typedef struct {
    MemoryRegion *mr;
    void *buffer;
    hwaddr addr;
    hwaddr len;
    bool in_use;
} BounceBuffer;

static BounceBuffer bounce;

typedef struct MapClient {
    QEMUBH *bh;
    QLIST_ENTRY(MapClient) link;
} MapClient;

QemuMutex map_client_list_lock;
static QLIST_HEAD(map_client_list, MapClient) map_client_list
    = QLIST_HEAD_INITIALIZER(map_client_list);

static void cpu_unregister_map_client_do(MapClient *client)
{
    QLIST_REMOVE(client, link);
    g_free(client);
}

static void cpu_notify_map_clients_locked(void)
{
    MapClient *client;

    while (!QLIST_EMPTY(&map_client_list)) {
        client = QLIST_FIRST(&map_client_list);
        qemu_bh_schedule(client->bh);
        cpu_unregister_map_client_do(client);
    }
}

void cpu_register_map_client(QEMUBH *bh)
{
    MapClient *client = g_malloc(sizeof(*client));

    qemu_mutex_lock(&map_client_list_lock);
    client->bh = bh;
    QLIST_INSERT_HEAD(&map_client_list, client, link);
    if (!atomic_read(&bounce.in_use)) {
        cpu_notify_map_clients_locked();
    }
    qemu_mutex_unlock(&map_client_list_lock);
}

void cpu_exec_init_all(void)
{
    qemu_mutex_init(&ram_list.mutex);
    /* The data structures we set up here depend on knowing the page size,
     * so no more changes can be made after this point.
     * In an ideal world, nothing we did before we had finished the
     * machine setup would care about the target page size, and we could
     * do this much later, rather than requiring board models to state
     * up front what their requirements are.
     */
    finalize_target_page_bits();
    io_mem_init();
    memory_map_init();
    qemu_mutex_init(&map_client_list_lock);
}

void cpu_unregister_map_client(QEMUBH *bh)
{
    MapClient *client;

    qemu_mutex_lock(&map_client_list_lock);
    QLIST_FOREACH(client, &map_client_list, link) {
        if (client->bh == bh) {
            cpu_unregister_map_client_do(client);
            break;
        }
    }
    qemu_mutex_unlock(&map_client_list_lock);
}

static void cpu_notify_map_clients(void)
{
    qemu_mutex_lock(&map_client_list_lock);
    cpu_notify_map_clients_locked();
    qemu_mutex_unlock(&map_client_list_lock);
}

bool address_space_access_valid(AddressSpace *as, hwaddr addr, int len, bool is_write)
{
    MemoryRegion *mr;
    hwaddr l, xlat;

    rcu_read_lock();
    while (len > 0) {
        l = len;
        mr = address_space_translate(as, addr, &xlat, &l, is_write);
        if (!memory_access_is_direct(mr, is_write)) {
            l = memory_access_size(mr, l, addr);
            if (!memory_region_access_valid(mr, xlat, l, is_write)) {
                rcu_read_unlock();
                return false;
            }
        }

        len -= l;
        addr += l;
    }
    rcu_read_unlock();
    return true;
}

static hwaddr
address_space_extend_translation(AddressSpace *as, hwaddr addr, hwaddr target_len,
                                 MemoryRegion *mr, hwaddr base, hwaddr len,
                                 bool is_write)
{
    hwaddr done = 0;
    hwaddr xlat;
    MemoryRegion *this_mr;

    for (;;) {
        target_len -= len;
        addr += len;
        done += len;
        if (target_len == 0) {
            return done;
        }

        len = target_len;
        this_mr = address_space_translate(as, addr, &xlat, &len, is_write);
        if (this_mr != mr || xlat != base + done) {
            return done;
        }
    }
}

QLIST_HEAD(rr_map_list, RR_MapList) rr_map_list
    = QLIST_HEAD_INITIALIZER(rr_map_list);

/* Map a physical memory region into a host virtual address.
 * May map a subset of the requested range, given by and returned in *plen.
 * May return NULL if resources needed to perform the mapping are exhausted.
 * Use only for reads OR writes - not for read-modify-write operations.
 * Use cpu_register_map_client() to know when retrying the map operation is
 * likely to succeed.
 */
void *address_space_map(AddressSpace *as,
                        hwaddr addr,
                        hwaddr *plen,
                        bool is_write)
{
    hwaddr len = *plen;
    hwaddr l, xlat;
    MemoryRegion *mr;
    void *ptr;

    if (len == 0) {
        return NULL;
    }

    l = len;
    rcu_read_lock();
    mr = address_space_translate(as, addr, &xlat, &l, is_write);

    if (!memory_access_is_direct(mr, is_write)) {
        if (atomic_xchg(&bounce.in_use, true)) {
            rcu_read_unlock();
            return NULL;
        }
        /* Avoid unbounded allocations */
        l = MIN(l, TARGET_PAGE_SIZE);
        bounce.buffer = qemu_memalign(TARGET_PAGE_SIZE, l);
        bounce.addr = addr;
        bounce.len = l;

        memory_region_ref(mr);
        bounce.mr = mr;
        if (!is_write) {
            address_space_read(as, addr, MEMTXATTRS_UNSPECIFIED,
                               bounce.buffer, l);
        }

        rcu_read_unlock();
        *plen = l;
        return bounce.buffer;
    }


    memory_region_ref(mr);
    *plen = address_space_extend_translation(as, addr, len, mr, xlat, l, is_write);
    ptr = qemu_ram_ptr_length(mr->ram_block, xlat, plen);
    rcu_read_unlock();

    if (!rr_in_replay()) {
        // Keep a list of these so we can find out when they change
        RR_MapList *region = g_malloc(sizeof(*region));
        region->addr = addr;
        region->len = *plen; // can't use len because it was modified
        region->ptr = ptr;
        region->crc = crc32(crc32(0, Z_NULL, 0), region->ptr, region->len);
        QLIST_INSERT_HEAD(&rr_map_list, region, link);
    }

    return ptr;
}

/* Unmaps a memory region previously mapped by address_space_map().
 * Will also mark the memory as dirty if is_write == 1.  access_len gives
 * the amount of memory that was actually read or written by the caller.
 */
void address_space_unmap(AddressSpace *as, void *buffer, hwaddr len,
                         int is_write, hwaddr access_len)
{
    if (buffer != bounce.buffer) {
        MemoryRegion *mr;
        ram_addr_t addr1;

        mr = memory_region_from_host(buffer, &addr1);
        assert(mr != NULL);
        if (is_write) {
            //bdg Save addr1,access_len,buffer contents
            if (rr_in_record()) {
                rr_device_mem_unmap_call_record(addr1, buffer, access_len, is_write);
            }
            invalidate_and_set_dirty(mr, addr1, access_len);
        }
        if (xen_enabled()) {
            xen_invalidate_map_cache_entry(buffer);
        }
        memory_region_unref(mr);

        // Remove it from the tracked map regions for rec/replay
        if (!rr_in_replay()) {
            RR_MapList *region;
            bool found = false;
            QLIST_FOREACH(region, &rr_map_list, link) {
                if (region->ptr == buffer && region->len == len) {
                    found = true;
                    break;
                }
            }
            if (found) {
                QLIST_REMOVE(region, link);
                g_free(region);
            }
        }

        return;
    }
    if (is_write) {
        address_space_write(as, bounce.addr, MEMTXATTRS_UNSPECIFIED,
                            bounce.buffer, access_len);
    }
    qemu_vfree(bounce.buffer);
    bounce.buffer = NULL;
    memory_region_unref(bounce.mr);
    atomic_mb_set(&bounce.in_use, false);
    cpu_notify_map_clients();
}

void *cpu_physical_memory_map(hwaddr addr,
                              hwaddr *plen,
                              int is_write)
{
    return address_space_map(&address_space_memory, addr, plen, is_write);
}

void cpu_physical_memory_unmap(void *buffer, hwaddr len,
                               int is_write, hwaddr access_len)
{
    return address_space_unmap(&address_space_memory, buffer, len, is_write, access_len);
}

#define ARG1_DECL                AddressSpace *as
#define ARG1                     as
#define SUFFIX
#define TRANSLATE(...)           address_space_translate(as, __VA_ARGS__)
#define IS_DIRECT(mr, is_write)  memory_access_is_direct(mr, is_write)
#define MAP_RAM(mr, ofs)         qemu_map_ram_ptr((mr)->ram_block, ofs)
#define INVALIDATE(mr, ofs, len) invalidate_and_set_dirty(mr, ofs, len)
#define RCU_READ_LOCK(...)       rcu_read_lock()
#define RCU_READ_UNLOCK(...)     rcu_read_unlock()
#include "memory_ldst.inc.c"

int64_t address_space_cache_init(MemoryRegionCache *cache,
                                 AddressSpace *as,
                                 hwaddr addr,
                                 hwaddr len,
                                 bool is_write)
{
    hwaddr l, xlat;
    MemoryRegion *mr;
    void *ptr;

    assert(len > 0);

    l = len;
    mr = address_space_translate(as, addr, &xlat, &l, is_write);
    if (!memory_access_is_direct(mr, is_write)) {
        return -EINVAL;
    }

    l = address_space_extend_translation(as, addr, len, mr, xlat, l, is_write);
    ptr = qemu_ram_ptr_length(mr->ram_block, xlat, &l);

    cache->xlat = xlat;
    cache->is_write = is_write;
    cache->mr = mr;
    cache->ptr = ptr;
    cache->len = l;
    memory_region_ref(cache->mr);

    return l;
}

void address_space_cache_invalidate(MemoryRegionCache *cache,
                                    hwaddr addr,
                                    hwaddr access_len)
{
    assert(cache->is_write);
    invalidate_and_set_dirty(cache->mr, addr + cache->xlat, access_len);
}

void address_space_cache_destroy(MemoryRegionCache *cache)
{
    if (!cache->mr) {
        return;
    }

    if (xen_enabled()) {
        xen_invalidate_map_cache_entry(cache->ptr);
    }
    memory_region_unref(cache->mr);
    cache->mr = NULL;
}

/* Called from RCU critical section.  This function has the same
 * semantics as address_space_translate, but it only works on a
 * predefined range of a MemoryRegion that was mapped with
 * address_space_cache_init.
 */
static inline MemoryRegion *address_space_translate_cached(
    MemoryRegionCache *cache, hwaddr addr, hwaddr *xlat,
    hwaddr *plen, bool is_write)
{
    assert(addr < cache->len && *plen <= cache->len - addr);
    *xlat = addr + cache->xlat;
    return cache->mr;
}

#define ARG1_DECL                MemoryRegionCache *cache
#define ARG1                     cache
#define SUFFIX                   _cached
#define TRANSLATE(...)           address_space_translate_cached(cache, __VA_ARGS__)
#define IS_DIRECT(mr, is_write)  true
#define MAP_RAM(mr, ofs)         (cache->ptr + (ofs - cache->xlat))
#define INVALIDATE(mr, ofs, len) ((void)0)
#define RCU_READ_LOCK()          ((void)0)
#define RCU_READ_UNLOCK()        ((void)0)
#include "memory_ldst.inc.c"

/* virtual memory access for debug (includes writing to ROM) */
int cpu_memory_rw_debug(CPUState *cpu, target_ulong addr,
                        uint8_t *buf, int len, int is_write)
{
    int l;
    hwaddr phys_addr;
    target_ulong page;

    cpu_synchronize_state(cpu);
    while (len > 0) {
        int asidx;
        MemTxAttrs attrs;

        page = addr & TARGET_PAGE_MASK;
        phys_addr = cpu_get_phys_page_attrs_debug(cpu, page, &attrs);
        asidx = cpu_asidx_from_attrs(cpu, attrs);
        /* if no physical page mapped, return an error */
        if (phys_addr == -1)
            return -1;
        l = (page + TARGET_PAGE_SIZE) - addr;
        if (l > len)
            l = len;
        phys_addr += (addr & ~TARGET_PAGE_MASK);
        if (is_write) {
            cpu_physical_memory_write_rom(cpu->cpu_ases[asidx].as,
                                          phys_addr, buf, l);
        } else {
            address_space_rw(cpu->cpu_ases[asidx].as, phys_addr,
                             MEMTXATTRS_UNSPECIFIED,
                             buf, l, 0);
        }
        len -= l;
        buf += l;
        addr += l;
    }
    return 0;
}

/*
 * Allows code that needs to deal with migration bitmaps etc to still be built
 * target independent.
 */
size_t qemu_target_page_bits(void)
{
    return TARGET_PAGE_BITS;
}

#endif

/*
 * A helper function for the _utterly broken_ virtio device model to find out if
 * it's running on a big endian machine. Don't do this at home kids!
 */
bool target_words_bigendian(void);
bool target_words_bigendian(void)
{
#if defined(TARGET_WORDS_BIGENDIAN)
    return true;
#else
    return false;
#endif
}

#ifndef CONFIG_USER_ONLY
bool cpu_physical_memory_is_io(hwaddr phys_addr)
{
    MemoryRegion*mr;
    hwaddr l = 1;
    bool res;

    rcu_read_lock();
    mr = address_space_translate(&address_space_memory,
                                 phys_addr, &phys_addr, &l, false);

    res = !(memory_region_is_ram(mr) || memory_region_is_romd(mr));
    rcu_read_unlock();
    return res;
}

int qemu_ram_foreach_block(RAMBlockIterFunc func, void *opaque)
{
    RAMBlock *block;
    int ret = 0;

    rcu_read_lock();
    QLIST_FOREACH_RCU(block, &ram_list.blocks, next) {
        ret = func(block->idstr, block->host, block->offset,
                   block->used_length, opaque);
        if (ret) {
            break;
        }
    }
    rcu_read_unlock();
    return ret;
}

/*
 * Unmap pages of memory from start to start+length such that
 * they a) read as 0, b) Trigger whatever fault mechanism
 * the OS provides for postcopy.
 * The pages must be unmapped by the end of the function.
 * Returns: 0 on success, none-0 on failure
 *
 */
int ram_block_discard_range(RAMBlock *rb, uint64_t start, size_t length)
{
    int ret = -1;

    uint8_t *host_startaddr = rb->host + start;

    if ((uintptr_t)host_startaddr & (rb->page_size - 1)) {
        error_report("ram_block_discard_range: Unaligned start address: %p",
                     host_startaddr);
        goto err;
    }

    if ((start + length) <= rb->used_length) {
        uint8_t *host_endaddr = host_startaddr + length;
        if ((uintptr_t)host_endaddr & (rb->page_size - 1)) {
            error_report("ram_block_discard_range: Unaligned end address: %p",
                         host_endaddr);
            goto err;
        }

        errno = ENOTSUP; /* If we are missing MADVISE etc */

        if (rb->page_size == qemu_host_page_size) {
#if defined(CONFIG_MADVISE)
            /* Note: We need the madvise MADV_DONTNEED behaviour of definitely
             * freeing the page.
             */
            ret = madvise(host_startaddr, length, MADV_DONTNEED);
#endif
        } else {
            /* Huge page case  - unfortunately it can't do DONTNEED, but
             * it can do the equivalent by FALLOC_FL_PUNCH_HOLE in the
             * huge page file.
             */
#ifdef CONFIG_FALLOCATE_PUNCH_HOLE
            ret = fallocate(rb->fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                            start, length);
#endif
        }
        if (ret) {
            ret = -errno;
            error_report("ram_block_discard_range: Failed to discard range "
                         "%s:%" PRIx64 " +%zx (%d)",
                         rb->idstr, start, length, ret);
        }
    } else {
        error_report("ram_block_discard_range: Overrun block '%s' (%" PRIu64
                     "/%zx/" RAM_ADDR_FMT")",
                     rb->idstr, start, length, rb->used_length);
    }

err:
    return ret;
}

#endif
