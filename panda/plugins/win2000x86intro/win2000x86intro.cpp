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

#include "qemu/rcu.h"
#include "qemu/rcu_queue.h"

#include "exec/address-spaces.h"

#include "wintrospection/wintrospection.h"
#include "wintrospection/wintrospection_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);
void on_get_libraries(CPUState *cpu, OsiProc *p, GArray **out);
PTR get_win2000_kpcr(CPUState *cpu);
HandleObject *get_win2000_handle_object(CPUState *cpu, uint32_t eproc, uint32_t handle);
}

#include <cstdio>
#include <cstdlib>

#ifdef TARGET_I386

#define KDBG_PSLML             0x048 // _KDDEBUGGER_DATA64.PsLoadedModuleList
#define EPROC_PEB_OFF          0x1b0 // _EPROCESS.Peb
#define PEB_LDR_OFF            0x00c // _PEB.Ldr
#define PEB_LDR_MEM_LINKS_OFF  0x014 // _PEB_LDR_DATA.InMemoryOrderModuleList
#define PEB_LDR_LOAD_LINKS_OFF 0x00c // _PEB_LDR_DATA.InLoadOrderModuleList


// Windows 2000 has a fixed location for the KPCR
PTR get_win2000_kpcr(CPUState *cpu) {
    return 0xFFDFF000;
}

// Loaded module list
static PTR lml;

static PTR get_loaded_module_list(CPUState *cpu) {

    if(lml) return lml;

    MemoryRegion *mr = memory_region_find(get_system_memory(), 0x2000000, 1).mr;

    rcu_read_lock();
    char *host_ptr = (char *)qemu_map_ram_ptr(mr->ram_block, 0);
    unsigned char *s;
    bool found=false;
    uint32_t i;

    // Locate the KDDEBUGGER_DATA64 structure
    for(i=0; i<mr->size-0x208; i++) {
        s = ((unsigned char *) host_ptr) + i;
    if(s[8] == '\0' && s[9] == '\0' && s[10] == '\0' && s[11] == '\0' &&
        s[12] == '\0' && s[13] == '\0' && s[14] == '\0' && s[15] == '\0' &&
        s[16] == 'K' && s[17] == 'D' && s[18] == 'B' && s[19] == 'G') {
            found=true;
        break;
    }
    }

    // Ensure the structure was located
    assert(found);

    // Store the virtual address of the loaded module list so we don't need
    // to repeat this work
    memcpy(&lml, s+KDBG_PSLML, sizeof(lml));

    rcu_read_unlock();
    return lml;
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

    PTR peb, ldr;
    PTR mod_first, mod_current, mod_next;
    peb = ldr = (PTR)NULL;
    mod_first = mod_current = mod_next = (PTR)NULL;

    // get module list: PEB->Ldr->InMemoryOrderModuleList
    if (-1 == panda_virtual_memory_rw(cpu, eproc_found + EPROC_PEB_OFF, (uint8_t *)&peb, sizeof(PTR), false))
        goto error;
    if (-1 == panda_virtual_memory_rw(cpu, peb + PEB_LDR_OFF, (uint8_t *)&ldr, sizeof(PTR), false))
        goto error;
    if (-1 == panda_virtual_memory_rw(cpu, ldr + PEB_LDR_MEM_LINKS_OFF, (uint8_t *)&mod_first, sizeof(PTR), false))
        goto error;

    // allocate GArray
    if (*out == NULL) {
        // g_array_sized_new() args: zero_term, clear, element_sz, reserved_sz
        *out = g_array_sized_new(false, false, sizeof(OsiModule), 128);
        g_array_set_clear_func(*out, (GDestroyNotify)free_osimodule_contents);
    }

    // fill GArray
    mod_current = mod_first;
    mod_next = get_next_mod(cpu, mod_current);
    while (mod_current != NULL && mod_next != mod_first) {
        add_mod(cpu, *out, mod_current, true);
        mod_current = mod_next;
        mod_next = get_next_mod(cpu, mod_current);
    };
    return;

error:
    *out = NULL;
    return;
}

void on_get_modules(CPUState *cpu, GArray **out) {
    PTR lml = get_loaded_module_list(cpu);
    PTR mod_first, mod_current, mod_next;
    mod_first = mod_current = mod_next = (PTR)NULL;

    // Dbg.PsLoadedModuleList
    if (-1 == panda_virtual_memory_rw(cpu, lml, (uint8_t *)&mod_first, sizeof(PTR), false))
    goto error;

    // allocate GArray
    if (*out == NULL) {
    // g_array_sized_new() args: zero_term, clear, element_sz, reserved_sz
    *out = g_array_sized_new(false, false, sizeof(OsiModule), 128);
    g_array_set_clear_func(*out, (GDestroyNotify)free_osimodule_contents);
    }

    // fill GArray
    mod_current = mod_first;
    mod_next = get_next_mod(cpu, mod_current);
    while (mod_current != NULL && mod_next != mod_first) {
        add_mod(cpu, *out, mod_current, false);
        mod_current = mod_next;
        mod_next = get_next_mod(cpu, mod_current);
    }
    return;

error:
    *out = NULL;
    return;
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

    //  printf ("processHandle_to_pid pObjectHeader = 0x%x\n", pObjectHeader);
    pObjectHeader |= 0x80000000;
    pObjectHeader &= ~0x00000007;

    return pObjectHeader;
}


HandleObject *get_win2000_handle_object(CPUState *cpu, uint32_t eproc, uint32_t handle) {
    uint32_t pObjectTable;
    uint32_t handleTable;
    if (-1 == panda_virtual_memory_rw(cpu, eproc+get_eproc_objtable_off(), (uint8_t *)&pObjectTable, 4, false)) {
        return NULL;
    }
    if (-1 == panda_virtual_memory_rw(cpu, pObjectTable + 0x08, (uint8_t *)&handleTable, 4, false)) {
        return NULL;
    }
    uint32_t pObjHeader = get_handle_table_entry(cpu, handleTable, handle);
    if (pObjHeader == 0) return NULL;
    uint32_t pObj = pObjHeader + 0x18;
    uint8_t objType = 0;
    if (-1 == panda_virtual_memory_rw(cpu, pObjHeader+get_obj_type_offset(), (uint8_t *)&objType, 1, false)) {
        return NULL;
    }
    HandleObject *ho = (HandleObject *)g_malloc(sizeof(HandleObject));
    ho->objType = objType;
    ho->pObj = pObj;
    return ho;
}



#endif

bool init_plugin(void *self) {
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    PPP_REG_CB("osi", on_get_libraries, on_get_libraries);
    PPP_REG_CB("osi", on_get_modules, on_get_modules);
    assert(init_wintrospection_api());
    return true;
#else
    return false;
#endif

}

void uninit_plugin(void *self) {
}
