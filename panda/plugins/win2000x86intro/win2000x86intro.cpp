/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */
#define __STDC_FORMAT_MACROS

#include <glib.h>
#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

extern "C" {

#include "osi/osi_types.h"
#include "osi/os_intro.h"

#ifndef CONFIG_DARWIN
#include "qemu/rcu.h"
#include "qemu/rcu_queue.h"
#endif

#include "exec/address-spaces.h"

#include "wintrospection/wintrospection.h"
#include "wintrospection/wintrospection_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);
void on_get_libraries(CPUState *cpu, OsiProc *p, GArray **out);
PTR get_win2000_kpcr(CPUState *cpu);
HandleObject *get_win2000_handle_object(CPUState *cpu, uint32_t eproc, uint32_t handle);
#ifndef CONFIG_DARWIN
PTR get_win2000_kddebugger_data(CPUState *cpu);
#endif
}

#include <cstdio>
#include <cstdlib>

#ifdef TARGET_I386

#define HANDLE_TABLE_L1_OFF    0x008    // _HANDLE_TABLE.Layer1
#define KDDEBUGGER_DATA_SIZE   0x208

#define HANDLE_LOCK_FLAG 0x80000000

// Windows 2000 has a fixed location for the KPCR
PTR get_win2000_kpcr(CPUState *cpu) {
    return 0xFFDFF000;
}

// i.e. return pointer to the object represented by this handle
static uint32_t get_handle_table_entry(CPUState *cpu, uint32_t pHandleTable, uint32_t handle) {
    uint32_t L1_index = (handle & HANDLE_MASK3) >> HANDLE_SHIFT3;
    uint32_t L1_table_off = handle_table_L1_addr(cpu, pHandleTable, L1_index);
    uint32_t L1_table;
    if(panda_virtual_memory_rw(cpu, L1_table_off, (uint8_t *) &L1_table, 4, false) == -1) return 0;

    uint32_t L2_index = (handle & HANDLE_MASK2) >> HANDLE_SHIFT2;
    uint32_t L2_table_off = handle_table_L2_addr(L1_table, L2_index);
    uint32_t L2_table;
    if(panda_virtual_memory_rw(cpu, L2_table_off, (uint8_t *) &L2_table, 4, false) == -1) return 0;

    uint32_t index = (handle & HANDLE_MASK1) >> HANDLE_SHIFT1;
    uint32_t pEntry = handle_table_L3_entry(pHandleTable, L2_table, index);
    uint32_t pObjectHeader;
    if ((panda_virtual_memory_rw(cpu, pEntry, (uint8_t *) &pObjectHeader, 4, false)) == -1) return 0;

    // In Windows 2000 (and supposedly Windows NT 4), the three low-order and
    // highest-order bit are flags.
    //
    // The remaining bits make up the pointer - sometimes. The lock flag must be
    // set get a valid pointer to the object since these are kernel objects and
    // they will always live in memory that is greater than 0x80000000. So to
    // get the pointer you have to set the high bit if it is not already locked
    // and mask off the lower three bits.
    //
    // Ref: Inside Microsoft Windows 2000, Third Edition, David A. Solomon, Mark
    // E. Russinovich.
    pObjectHeader |= HANDLE_LOCK_FLAG;
    pObjectHeader &= TABLE_MASK;

    return pObjectHeader;
}


HandleObject *get_win2000_handle_object(CPUState *cpu, uint32_t eproc, uint32_t handle) {
    uint32_t pObjectTable;
    uint32_t handleTable;
    if (-1 == panda_virtual_memory_rw(cpu, eproc+get_eproc_objtable_off(), (uint8_t *)&pObjectTable, 4, false)) {
        return NULL;
    }
    if (-1 == panda_virtual_memory_read(cpu, pObjectTable + HANDLE_TABLE_L1_OFF,
                                        (uint8_t *)&handleTable,
                                        sizeof(handleTable))) {
        return NULL;
    }
    uint32_t pObjHeader = get_handle_table_entry(cpu, handleTable, handle);
    if (pObjHeader == 0) return NULL;
    uint32_t pObj = pObjHeader + OBJECT_HEADER_BODY_OFFSET;
    uint8_t objType = 0;
    if (-1 == panda_virtual_memory_rw(cpu, pObjHeader+get_obj_type_offset(), (uint8_t *)&objType, 1, false)) {
        return NULL;
    }
    HandleObject *ho = (HandleObject *)g_malloc(sizeof(HandleObject));
    ho->objType = objType;
    ho->pObj = pObj;
    return ho;
}

#ifndef CONFIG_DARWIN
// Returns the physical address of KDDEBUGGER_DATA64.
PTR get_win2000_kddebugger_data(CPUState *cpu)
{
    static PTR cached_kdbg = -1;
    if (cached_kdbg != -1) {
        return cached_kdbg;
    }

    MemoryRegion *mr = memory_region_find(get_system_memory(), 0x2000000, 1).mr;
    rcu_read_lock();
    uint8_t *host_ptr = (uint8_t *)qemu_map_ram_ptr(mr->ram_block, 0);
    uint8_t signature[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                           0x0, 0x0, 'K', 'D', 'B', 'G'};

    for (int i = 0; i < int128_get64(mr->size) - KDDEBUGGER_DATA_SIZE; i++) {
        if (0 == memcmp(signature, host_ptr + i, sizeof(signature))) {
            // We subtract eight bytes from the current position because of the
            // list entry field size. This gives us the start of the
            // KDDEBUGGER_DATA structure.
            cached_kdbg = i - 8;
            break;
        }
    }
    rcu_read_unlock();

    return cached_kdbg;
}
#endif

#endif

bool init_plugin(void *self) {
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    assert(init_wintrospection_api());
    return true;
#else
    return false;
#endif

}

void uninit_plugin(void *self) {
}
