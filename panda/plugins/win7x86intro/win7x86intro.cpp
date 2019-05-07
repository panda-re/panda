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

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

extern "C" {

#include "osi/osi_types.h"
#include "osi/os_intro.h"

#include "wintrospection/wintrospection.h"
#include "wintrospection/wintrospection_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);
void on_get_libraries(CPUState *, OsiProc *p, GArray **out);
PTR get_win7_kpcr(CPUState *cpu);
HandleObject *get_win7_handle_object(CPUState *cpu, uint32_t eproc, uint32_t handle);
PTR get_win7_kdbg(CPUState *cpu);
}

#include <cstdio>
#include <cstdlib>

#ifdef TARGET_I386

#define KMODE_FS               0x030 // Segment number of FS in kernel mode
#define KPCR_KDVERSION_OFF     0x034  // _KPCR.KdVersionBlock
#define KDVERSION_DDL_OFF      0x020  // _DBGKD_GET_VERSION64.DebuggerDataList

// XXX: this will have to change for 64-bit
PTR get_win7_kpcr(CPUState *cpu) {
    // Read the kernel-mode FS segment base
    uint32_t e1, e2;
    PTR fs_base;

    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    // Read out the two 32-bit ints that make up a segment descriptor
    panda_virtual_memory_rw(cpu, env->gdt.base + KMODE_FS, (uint8_t *)&e1, sizeof(PTR), false);
    panda_virtual_memory_rw(cpu, env->gdt.base + KMODE_FS + 4, (uint8_t *)&e2, sizeof(PTR), false);

    // Turn wacky segment into base
    fs_base = (e1 >> 16) | ((e2 & 0xff) << 16) | (e2 & 0xff000000);

    return fs_base;
}

// i.e. return pointer to the object represented by this handle
static uint32_t get_handle_table_entry(CPUState *cpu, uint32_t pHandleTable, uint32_t handle) {
    uint32_t tableCode, tableLevels;
    // get tablecode
    panda_virtual_memory_rw(cpu, pHandleTable, (uint8_t *)&tableCode, 4, false);
    // extract levels
    tableLevels = tableCode & LEVEL_MASK;
    if (tableLevels > 2) {
        return 0;
    }
    uint32_t pEntry=0;
    if (tableLevels == 0) {
        uint32_t index = (handle & HANDLE_MASK1) >> HANDLE_SHIFT1;
        pEntry = handle_table_L1_entry(cpu, pHandleTable, index);
    }
    if (tableLevels == 1) {
        uint32_t L1_index = (handle & HANDLE_MASK2) >> HANDLE_SHIFT2;
        uint32_t L1_table_off = handle_table_L1_addr(cpu, pHandleTable, L1_index);
        uint32_t L1_table;
        panda_virtual_memory_rw(cpu, L1_table_off, (uint8_t *) &L1_table, 4, false);
        uint32_t index = (handle & HANDLE_MASK1) >> HANDLE_SHIFT1;
        pEntry = handle_table_L2_entry(pHandleTable, L1_table, index);
    }
    if (tableLevels == 2) {
        uint32_t L1_index = (handle & HANDLE_MASK3) >> HANDLE_SHIFT3;
        uint32_t L1_table_off = handle_table_L1_addr(cpu, pHandleTable, L1_index);
        uint32_t L1_table;
        panda_virtual_memory_rw(cpu, L1_table_off, (uint8_t *) &L1_table, 4, false);
        uint32_t L2_index = (handle & HANDLE_MASK2) >> HANDLE_SHIFT2;
        uint32_t L2_table_off = handle_table_L2_addr(L1_table, L2_index);
        uint32_t L2_table;
        panda_virtual_memory_rw(cpu, L2_table_off, (uint8_t *) &L2_table, 4, false);
        uint32_t index = (handle & HANDLE_MASK1) >> HANDLE_SHIFT1;
        pEntry = handle_table_L3_entry(pHandleTable, L2_table, index);
    }
    uint32_t pObjectHeader;
    if ((panda_virtual_memory_rw(cpu, pEntry, (uint8_t *) &pObjectHeader, 4, false)) == -1) {
        return 0;
    }

    // Like in Windows 2000, the entry here needs to be masked off. However, it
    // appears that starting in Windows XP, they've done away with the lock
    // flag. The lower three bits mask should be consistent across Windows
    // versions because of the object alignment.
    //
    // No obvious reference.
    pObjectHeader &= TABLE_MASK;

    return pObjectHeader;
}


HandleObject *get_win7_handle_object(CPUState *cpu, uint32_t eproc, uint32_t handle) {
    uint32_t pObjectTable;
    if (-1 == panda_virtual_memory_rw(cpu, eproc+get_eproc_objtable_off(), (uint8_t *)&pObjectTable, 4, false)) {
        return NULL;
    }
    uint32_t pObjHeader = get_handle_table_entry(cpu, pObjectTable, handle);
    if (pObjHeader == 0) return NULL;
    uint32_t pObj = pObjHeader + OBJECT_HEADER_BODY_OFFSET;
    uint8_t objType = 0;
    if (-1 == panda_virtual_memory_rw(cpu, pObjHeader+get_obj_type_offset(), &objType, 1, false)) {
        return NULL;
    }
    HandleObject *ho = (HandleObject *) malloc(sizeof(HandleObject));
    ho->objType = objType;
    ho->pObj = pObj;
    return ho;
}

PTR get_win7_kdbg(CPUState *cpu)
{
    PTR kpcr = get_win7_kpcr(cpu);
    PTR kdversion, kddl, kddlp;
    if (-1 == panda_virtual_memory_rw(cpu, kpcr + KPCR_KDVERSION_OFF,
                                      (uint8_t *)&kdversion, sizeof(PTR),
                                      false)) {
        return 0;
    }
    // DebuggerDataList is a pointer to a pointer to the _KDDEBUGGER_DATA64
    // So we need to dereference it twice.
    if (-1 == panda_virtual_memory_rw(cpu, kdversion + KDVERSION_DDL_OFF,
                                      (uint8_t *)&kddlp, sizeof(PTR), false)) {
        return 0;
    }
    if (-1 == panda_virtual_memory_rw(cpu, kddlp, (uint8_t *)&kddl, sizeof(PTR),
                                      false)) {
        return 0;
    }
    return panda_virt_to_phys(cpu, kddl);
}

#endif

bool init_plugin(void *self) {
#ifdef TARGET_I386
    init_wintrospection_api();
    return true;
#else
    return false;
#endif

}

void uninit_plugin(void *self) { }
