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
PTR get_winxp_kpcr(CPUState *cpu);
HandleObject *get_winxp_handle_object(CPUState *cpu, uint32_t eproc,
                                      uint32_t handle);
}

#include <cstdio>
#include <cstdlib>

#ifdef TARGET_I386

#define KMODE_FS               0x030 // Segment number of FS in kernel mode
#define KPCR_KDVERSION_OFF     0x034 // _KPCR.KdVersionBlock
#define KDVERSION_DDL_OFF      0x020 // _DBGKD_GET_VERSION64.DebuggerDataList
#define KDBG_PSLML             0x048 // _KDDEBUGGER_DATA64.PsLoadedModuleList
#define EPROC_PEB_OFF          0x1b0 // _EPROCESS.Peb
#define PEB_LDR_OFF            0x00c // _PEB.Ldr
#define PEB_LDR_MEM_LINKS_OFF  0x014 // _PEB_LDR_DATA.InMemoryOrderModuleLinks
#define PEB_LDR_LOAD_LINKS_OFF 0x00c // _PEB_LDR_DATA.InMemoryOrderModuleLinks
#define LDR_LOAD_LINKS_OFF     0x000 // _LDR_DATA_TABLE_ENTRY.InLoadOrderLinks
#define OBJ_TYPE_INDEX_OFF     0x04c // _OBJECT_TYPE.Index

// XXX: this will have to change for 64-bit
PTR get_winxp_kpcr(CPUState *cpu)
{
    return 0xFFDFF000;
}

static PTR get_kdbg(CPUState *cpu)
{
    PTR kpcr = get_winxp_kpcr(cpu);
    PTR kdversion, kddl, kddlp;
    if (-1 == panda_virtual_memory_rw(cpu, kpcr+KPCR_KDVERSION_OFF, (uint8_t
*)&kdversion, sizeof(PTR), false)) { return 0;
    }
    // DebuggerDataList is a pointer to a pointer to the _KDDEBUGGER_DATA64
    // So we need to dereference it twice.
    if (-1 == panda_virtual_memory_rw(cpu, kdversion+KDVERSION_DDL_OFF, (uint8_t
*)&kddlp, sizeof(PTR), false)) { return 0;
    }
    if (-1 == panda_virtual_memory_rw(cpu, kddlp, (uint8_t *)&kddl, sizeof(PTR),
false)) { return 0;
    }
    return kddl;
}

void on_get_modules(CPUState *cpu, GArray **out) {
    PTR kdbg = get_kdbg(cpu);
    PTR PsLoadedModuleList;
    PTR mod_current = (PTR)NULL;

    // Dbg.PsLoadedModuleList
    if (-1 == panda_virtual_memory_rw(cpu, kdbg + KDBG_PSLML,
                                      (uint8_t *)&PsLoadedModuleList,
                                      sizeof(PTR), false))
        goto error;

    if (*out == NULL) {
        // g_array_sized_new() args: zero_term, clear, element_sz, reserved_sz
        *out = g_array_sized_new(false, false, sizeof(OsiModule), 128);
        g_array_set_clear_func(*out, (GDestroyNotify)free_osimodule_contents);
        }

        mod_current = get_next_mod(cpu, PsLoadedModuleList);

        // We want while loop here -- we are starting at the head,
        // which is not a valid module
        while (mod_current != NULL && mod_current != PsLoadedModuleList) {
            add_mod(cpu, *out, mod_current, false);
            mod_current = get_next_mod(cpu, mod_current);
        }
        return;

    error:
        *out = NULL;
        return;
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

    // Like in Windows 2000, the entry here needs to be masked off. However, the
    // lock flag was moved to the low-order bit. So we only need to mask off the
    // lower three bits of the entry.
    //
    // Russinovich, Mark E., and David A. Solomon. Microsoft Windows
    //     Internals, Fourth Edition: Microsoft Windows Server 2003, Windows XP,
    //     and Windows 2000. Microsoft Press, 2005, pp. 139.
    pObjectHeader &= TABLE_MASK;

    return pObjectHeader;
}

HandleObject *get_winxp_handle_object(CPUState *cpu, uint32_t eproc,
                                      uint32_t handle)
{
    // Obtain the handle table (also called the object table).
    uint32_t pObjectTable;
    if (-1 == panda_virtual_memory_rw(cpu, eproc+get_eproc_objtable_off(), (uint8_t *)&pObjectTable, 4, false)) {
        return NULL;
    }

    // Given the handle, lookup the object's header in the table.
    uint32_t pObjHeader = get_handle_table_entry(cpu, pObjectTable, handle);
    if (pObjHeader == 0) {
        return NULL;
    }

    // Once we have the header, we can get the object's body.
    uint32_t pObj = pObjHeader + OBJECT_HEADER_BODY_OFFSET;

    // In Windows XP, we need to look at the _OBJECT_TYPE struct to get the type
    // index.
    uint32_t pObjType;
    if (-1 == panda_virtual_memory_read(cpu, pObjHeader + get_obj_type_offset(),
                                        (uint8_t *)&pObjType,
                                        sizeof(pObjType))) {
        return NULL;
    }
    uint8_t objType = 0;
    if (-1 == panda_virtual_memory_read(cpu, pObjType + OBJ_TYPE_INDEX_OFF,
                                        (uint8_t *)&objType, sizeof(objType))) {
        return NULL;
    }

    // Construct our handle object and return.
    HandleObject *ho = (HandleObject *) malloc(sizeof(HandleObject));
    ho->objType = objType;
    ho->pObj = pObj;
    return ho;
}

#endif

bool init_plugin(void *self) {
#ifdef TARGET_I386
    PPP_REG_CB("osi", on_get_modules, on_get_modules);
    init_wintrospection_api();
    return true;
#else
    return false;
#endif

}

void uninit_plugin(void *self) { }
