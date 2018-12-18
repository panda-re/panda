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
}

#include <cstdio>
#include <cstdlib>

#ifdef TARGET_I386

#define KMODE_FS               0x030 // Segment number of FS in kernel mode
#define KPCR_KDVERSION_OFF     0x034  // _KPCR.KdVersionBlock
#define KDVERSION_DDL_OFF      0x020  // _DBGKD_GET_VERSION64.DebuggerDataList
#define KDBG_PSLML             0x048  // _KDDEBUGGER_DATA64.PsLoadedModuleList
#define EPROC_PEB_OFF          0x1a8 // _EPROCESS.Peb
#define PEB_LDR_OFF            0x00c // _PEB.Ldr
#define PEB_LDR_MEM_LINKS_OFF  0x014 // _PEB_LDR_DATA.InMemoryOrderModuleLinks
#define PEB_LDR_LOAD_LINKS_OFF 0x00c // _PEB_LDR_DATA.InMemoryOrderModuleLinks
#define LDR_LOAD_LINKS_OFF     0x000 // _LDR_DATA_TABLE_ENTRY.InLoadOrderLinks

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

static PTR get_kdbg(CPUState *cpu) {
    PTR kpcr = get_win7_kpcr(cpu);
    PTR kdversion, kddl, kddlp;
    if (-1 == panda_virtual_memory_rw(cpu, kpcr+KPCR_KDVERSION_OFF, (uint8_t *)&kdversion, sizeof(PTR), false)) {
        return 0;
    }
    // DebuggerDataList is a pointer to a pointer to the _KDDEBUGGER_DATA64
    // So we need to dereference it twice.
    if (-1 == panda_virtual_memory_rw(cpu, kdversion+KDVERSION_DDL_OFF, (uint8_t *)&kddlp, sizeof(PTR), false)) {
        return 0;
    }
    if (-1 == panda_virtual_memory_rw(cpu, kddlp, (uint8_t *)&kddl, sizeof(PTR), false)) {
        return 0;
    }
    return kddl;
}




void on_get_libraries(CPUState *cpu, OsiProc *p, GArray **out) {
    // search for process
    PTR eproc_first, eproc_cur, eproc_found;
    eproc_first = eproc_cur = get_current_proc(cpu);
    eproc_found = (PTR)NULL;
    if (eproc_first == NULL) goto error;
    do {
        if (eproc_cur == p->taskd) {
            eproc_found = eproc_cur;
            break;
        }
        eproc_cur = get_next_proc(cpu, eproc_cur);
    } while (eproc_cur != NULL && eproc_cur != eproc_first);
    if (eproc_found == NULL) goto error;

    if (*out == NULL) {
        // g_array_sized_new() args: zero_term, clear, element_sz, reserved_sz
        *out = g_array_sized_new(false, false, sizeof(OsiModule), 128);
        g_array_set_clear_func(*out, (GDestroyNotify)free_osimodule_contents);
    }

    PTR peb, ldr;
    PTR mod_first, mod_current;
    peb = ldr = (PTR)NULL;
    mod_first = mod_current = (PTR)NULL;

    // get module list: PEB->Ldr->InMemoryOrderModuleList
    if (-1 == panda_virtual_memory_rw(cpu, eproc_found+EPROC_PEB_OFF, (uint8_t *)&peb, sizeof(PTR), false))
        goto error;
    if (-1 == panda_virtual_memory_rw(cpu, peb+PEB_LDR_OFF, (uint8_t *)&ldr, sizeof(PTR), false))
        goto error;
    if (ldr == NULL)
        goto error;

    // Fake "first mod": the address of where the list head would
    // be if it were a LDR_DATA_TABLE_ENTRY
    mod_first = ldr+PEB_LDR_LOAD_LINKS_OFF-LDR_LOAD_LINKS_OFF;
    mod_current = get_next_mod(cpu, mod_first);

    // We want while loop here -- we are starting at the head,
    // which is not a valid module
    while (mod_current != NULL && mod_current != mod_first) {
        add_mod(cpu, *out, mod_current, false);
        mod_current = get_next_mod(cpu, mod_current);
    }
    return;

error:
    *out = NULL;
    return;
}

void on_get_modules(CPUState *cpu, GArray **out) {
    PTR kdbg = get_kdbg(cpu);
    PTR PsLoadedModuleList;
    PTR mod_current = (PTR)NULL;

    // Dbg.PsLoadedModuleList
    if (-1 == panda_virtual_memory_rw(cpu, kdbg+KDBG_PSLML, (uint8_t *)&PsLoadedModuleList, sizeof(PTR), false))
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
    //printf ("tableCode = 0x%x\n", tableCode);
    // extract levels
    tableLevels = tableCode & LEVEL_MASK;
    //printf("tableLevels = %d\n", tableLevels);
    //  assert (tableLevels <= 2);
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
    //  printf ("processHandle_to_pid pObjectHeader = 0x%x\n", pObjectHeader);
    pObjectHeader &= ~0x00000007;

    return pObjectHeader;
}


HandleObject *get_win7_handle_object(CPUState *cpu, uint32_t eproc, uint32_t handle) {
    uint32_t pObjectTable;
    if (-1 == panda_virtual_memory_rw(cpu, eproc+get_eproc_objtable_off(), (uint8_t *)&pObjectTable, 4, false)) {
        return NULL;
    }
    uint32_t pObjHeader = get_handle_table_entry(cpu, pObjectTable, handle);
    if (pObjHeader == 0) return NULL;
    uint32_t pObj = pObjHeader + 0x18;
    uint8_t objType = 0;
    if (-1 == panda_virtual_memory_rw(cpu, pObjHeader+get_obj_type_offset(), &objType, 1, false)) {
        return NULL;
    }
    HandleObject *ho = (HandleObject *) malloc(sizeof(HandleObject));
    ho->objType = objType;
    ho->pObj = pObj;
    return ho;
}


#endif

bool init_plugin(void *self) {
#ifdef TARGET_I386
    PPP_REG_CB("osi", on_get_libraries, on_get_libraries);
    PPP_REG_CB("osi", on_get_modules, on_get_modules);
    init_wintrospection_api();
    return true;
#else
    return false;
#endif

}

void uninit_plugin(void *self) { }
