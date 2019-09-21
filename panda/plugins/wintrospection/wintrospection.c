/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *  Tom Boning             tboning@mit.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */
#define __STDC_FORMAT_MACROS

#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <iconv.h>

#include "panda/rr/rr_log.h"

#include "osi/osi_types.h"
#include "osi/os_intro.h"

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include "panda/plog.h"

#include "syscalls2/syscalls_ext_typedefs.h"

#include "wintrospection.h"
#include "wintrospection_int_fns.h"

#include "win2000x86intro/win2000x86intro_ext.h"
#include "win7x86intro/win7x86intro_ext.h"
#include "winxpx86intro/winxpx86intro_ext.h"

#include "glib.h"

bool init_plugin(void *);
void uninit_plugin(void *);

// this stuff only makes sense for win x86 32-bit
#ifdef TARGET_I386

// Constants that are the same in all supported versions of windows
// Supports: Windows 2000 SP4, XP SP3, and Windows 7 SP1.
#define KPCR_CURTHREAD_OFF   0x124 // _KPCR.PrcbData.CurrentThread
#define EPROC_DTB_OFF        0x018 // _EPROCESS.Pcb.DirectoryTableBase
#define EPROC_TYPE_OFF       0x000 // _EPROCESS.Pcb.Header.Type
#define EPROC_SIZE_OFF       0x002 // _EPROCESS.Pcb.Header.Size
#define EPROC_TYPE           0x003 // Value of Type
#define EPROC_DTB_OFF        0x018 // _EPROCESS.Pcb.DirectoryTableBase
#define PEB_PEB_LDR_DATA_OFF 0x00c // _PEB.Ldr
#define PEB_LDR_DATA_LOAD_LIST_OFF 0x00c // _PEB_LDR_DATA.InLoadOrderModuleList
#define LDR_LOAD_LINKS_OFF   0x000 // _LDR_DATA_TABLE_ENTRY.InLoadOrderLinks
#define LDR_BASE_OFF         0x018 // _LDR_DATA_TABLE_ENTRY.DllBase
#define LDR_SIZE_OFF         0x020 // _LDR_DATA_TABLE_ENTRY.SizeOfImage
#define LDR_BASENAME_OFF     0x02c // _LDR_DATA_TABLE_ENTRY.BaseDllName
#define LDR_FILENAME_OFF     0x024 // _LDR_DATA_TABLE_ENTRY.FullDllName
#define OBJNAME_OFF          0x008
#define FILE_OBJECT_NAME_OFF 0x030
#define FILE_OBJECT_POS_OFF  0x038
#define PROCESS_PARAMETERS_OFF 0x010 // PEB.ProcessParameters
#define UNICODE_WORKDIR_OFF 0x24     // ProcessParameters.WorkingDirectory
// KDDEBUGGER_DATA64.PsActiveProcessHead
#define KDDBG64_LOADED_MOD_HEAD_OFF 0x048
// KDDEBUGGER_DATA64.PsLoadedModuleList
#define KDDBG64_ACTIVE_PROCESS_HEAD_OFF 0x50
// _CLIENT_ID.UniqueThread
#define CLIENT_ID_UNIQUE_THREAD 0x4

// "Constants" specific to the guest operating system.
// These are initialized in the init_plugin function.
static uint32_t kthread_kproc_off;  // _KTHREAD.Process
static uint32_t kthread_cid_off;    // _ETHREAD._KTHREAD.Cid
static uint32_t eproc_pid_off;      // _EPROCESS.UniqueProcessId
static uint32_t eproc_ppid_off;     // _EPROCESS.InheritedFromUniqueProcessId
static uint32_t eproc_name_off;     // _EPROCESS.ImageFileName
static uint32_t eproc_objtable_off; // _EPROCESS.ObjectTable
static uint32_t
    eproc_ppeb_off; // _EPROCESS.Peb (pointer to process environment block)
static uint32_t eproc_size;         // Value of Size
static uint32_t eproc_links_off;    // _EPROCESS.ActiveProcessLinks
static uint32_t obj_type_file;      // FILE object type
static uint32_t obj_type_key;       // KEY object type
static uint32_t obj_type_process;   // PROCESS object type
static uint32_t obj_type_offset;    // XXX_OBJECT.Type (offset from start of OBJECT_TYPE_HEADER)
static uint32_t ntreadfile_esp_off; // Number of bytes left on stack when NtReadFile returns

// Function pointer, returns location of KPCR structure.  OS-specific.
static PTR(*get_kpcr)(CPUState *cpu);

// Function pointer, returns handle table entry.  OS-specific.
static HandleObject *(*get_handle_object)(CPUState *cpu, PTR eproc, uint32_t handle);

// Function pointer, returns location of KDDEBUGGER_DATA<32|64> data structure.
// OS-specific.
static PTR (*get_kddebugger_data)(CPUState *cpu);

char *make_pagedstr(void) {
    char *m = g_strdup("(paged)");
    assert(m);
    return m;
}

// Gets a unicode string. Does its own mem allocation.
// Output is a null-terminated UTF8 string
char *get_unicode_str(CPUState *cpu, PTR ustr) {
    uint16_t size = 0;
    PTR str_ptr = 0;
    if (-1 == panda_virtual_memory_rw(cpu, ustr, (uint8_t *)&size, 2, false)) {
        return make_pagedstr();
    }

    // Unicode Strings can be zero length. In this case, just return an empty
    // string.
    if (size == 0) {
        return g_strdup("");
    }

    // Clamp size
    if (size > 1024) size = 1024;
    if (-1 == panda_virtual_memory_rw(cpu, ustr+4, (uint8_t *)&str_ptr, 4, false)) {
        return make_pagedstr();
    }

    gchar *in_str = (gchar *)g_malloc0(size);
    if (-1 == panda_virtual_memory_rw(cpu, str_ptr, (uint8_t *)in_str, size, false)) {
        g_free(in_str);
        return make_pagedstr();
    }

    gsize bytes_written = 0;
    gchar *out_str = g_convert(in_str, size,
            "UTF-8", "UTF-16LE", NULL, &bytes_written, NULL);

    // An abundance of caution: we copy it over to something allocated
    // with our own malloc. In the future we need to provide a way for
    // someone else to free the memory allocated in here...
    char *ret = (char *)g_malloc(bytes_written+1);
    memcpy(ret, out_str, bytes_written+1);
    g_free(in_str);
    g_free(out_str);
    return ret;
}

void add_mod(CPUState *cpu, GArray *ms, PTR mod, bool ignore_basename) {
    OsiModule m;
    memset(&m, 0, sizeof(OsiModule));
    fill_osimod(cpu, &m, mod, ignore_basename);
    g_array_append_val(ms, m);
}

void on_get_current_process(CPUState *cpu, OsiProc **out) {
    PTR eproc = get_current_proc(cpu);
    if(eproc) {
        OsiProc *p = (OsiProc *)g_malloc(sizeof(OsiProc));
        fill_osiproc(cpu, p, eproc);
        *out = p;
    } else {
        *out = NULL;
    }
}

void on_get_current_process_handle(CPUState *cpu, OsiProcHandle **out) {
    PTR eproc = get_current_proc(cpu);
    if(eproc) {
        OsiProcHandle *h = (OsiProcHandle *)g_malloc(sizeof(OsiProcHandle));
        fill_osiprochandle(cpu, h, eproc);
        *out = h;
    } else {
        *out = NULL;
    }
}

void on_get_libraries(CPUState *cpu, OsiProc *p, GArray **out)
{
    *out = NULL;
    if (p == NULL) {
        return;
    }

    PTR eproc = p->taskd;
    PTR ptr_peb;
    // EPROCESS is allocated from the non-paged pool, so it should
    // accessible at any time via its virtual address.
    if (-1 == panda_virtual_memory_read(cpu, eproc + eproc_ppeb_off,
                                        (uint8_t *)&ptr_peb, sizeof(ptr_peb))) {
        fprintf(stderr, "Could not read PEB Pointer from _EPROCESS!\n");
        return;
    }

    // Since we are getting the libraries for a specified process, we have to
    // make sure that we are looking in the address space of the process that
    // was passed in. We will temporarily override CR3 with the value specified
    // in _EPROCESS.Pcb.DirectoryTableBase. Again, since EPROCESS is allocated
    // from the non-paged pool this shouldn't fail.
    uint32_t dtb = -1;
    if (panda_virtual_memory_read(cpu, eproc + EPROC_DTB_OFF, (uint8_t *)&dtb,
                                  sizeof(dtb))) {
        fprintf(stderr, "Could not read DirectoryTableBase from _EPROCESS!\n");
        return;
    }
#ifdef TARGET_I386
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    target_ulong cur_cr3 = env->cr[3];
    env->cr[3] = dtb;
#endif

    // Get the location of the _PEB_LDR_DATA structure which contains the head
    // of the DLL listing.
    PTR ptr_peb_ldr_data;
    if (-1 == panda_virtual_memory_read(cpu, ptr_peb + PEB_PEB_LDR_DATA_OFF,
                                        (uint8_t *)&ptr_peb_ldr_data,
                                        sizeof(ptr_peb_ldr_data))) {
        // We fail silently here - _PEB is part of the paged pool, so its
        // possible that this is paged out and nothing is wrong.
        return;
    }

    bool reached_paged_entry = false;
    PTR sentinel = ptr_peb_ldr_data + PEB_LDR_DATA_LOAD_LIST_OFF;
    PTR cur_entry = sentinel;
    do {
        // Read the current list entry Flink pointer.
        if (-1 == panda_virtual_memory_read(cpu, cur_entry,
                                            (uint8_t *)&cur_entry,
                                            sizeof(cur_entry))) {
            fprintf(stderr, "Could not read next entry in module list.\n");
            break;
        }

        // If we've reached the sentinel, we're done.
        if (cur_entry == sentinel) {
            break;
        }

        // We're reasonbly sure we've found a library, add it to the list.
        // Note, the library may be paged out and if so, we stop iterating.
        PTR ptr_ldr_data_table_entry = cur_entry - LDR_LOAD_LINKS_OFF;
        char *name =
            get_unicode_str(cpu, ptr_ldr_data_table_entry + LDR_BASENAME_OFF);
        char *filename =
            get_unicode_str(cpu, ptr_ldr_data_table_entry + LDR_FILENAME_OFF);
        PTR base = -1;
        if (-1 == panda_virtual_memory_read(
                      cpu, ptr_ldr_data_table_entry + LDR_BASE_OFF,
                      (uint8_t *)&base, sizeof(base))) {
            // If this fails, we assume that this LDR_DATA_TABLE_ENTRY is paged
            reached_paged_entry = true;
        }
        PTR size = -1;
        if (-1 == panda_virtual_memory_read(
                      cpu, ptr_ldr_data_table_entry + LDR_SIZE_OFF,
                      (uint8_t *)&size, sizeof(size))) {
            // If this fails, we assume that this LDR_DATA_TABLE_ENTRY is paged
            reached_paged_entry = true;
        }

        OsiModule mod;
        if (NULL == *out) {
            *out = g_array_sized_new(false, false, sizeof(mod), 128);
            g_array_set_clear_func(*out,
                                   (GDestroyNotify)free_osimodule_contents);
        }
        mod.modd = ptr_ldr_data_table_entry;
        mod.base = base;
        mod.size = size;
        mod.name = name;
        mod.file = filename;
        g_array_append_val(*out, mod);
    } while (false == reached_paged_entry);

    // Now that we've gotten the libraries, we need to restore CR3.
#ifdef TARGET_I386
    env->cr[3] = cur_cr3;
#endif
}

void on_get_modules(CPUState *cpu, GArray **out)
{
    PTR kdbg = get_kddebugger_data(cpu);
    PTR PsLoadedModuleList = 0xFFFFFFFF;
    PTR mod_current = 0x0;

    // Dbg.PsLoadedModuleList
    if (-1 == panda_physical_memory_rw(kdbg + KDDBG64_LOADED_MOD_HEAD_OFF,
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
    while (mod_current != 0x0 && mod_current != PsLoadedModuleList) {
        add_mod(cpu, *out, mod_current, false);
        mod_current = get_next_mod(cpu, mod_current);
    }
    return;

error:
    *out = NULL;
    return;
}

void on_get_processes(CPUState *cpu, GArray **out) {
    // The process list in NT can be iterated by starting at the
    // nt!PsActiveProcessHead symbol. The symbol points to an nt!_LIST_ENTRY
    // that acts as a sentinel node for the process list, so we can use it as a
    // reference point to start and stop iterating.

    // Assume failure until we reach the first process, so set the output to
    // null.
    *out = NULL;

    // Try to get the nt!PsActiveProcessHead from the KDDEBUGGER_DATA64 struct.
    // Note that the result of kddebugger_data returns a physical address.
    PTR kddebugger_data = get_kddebugger_data(cpu);
    PTR sentinel = -1;
    if (-1 == panda_physical_memory_rw(
                  kddebugger_data + KDDBG64_ACTIVE_PROCESS_HEAD_OFF,
                  (uint8_t *)&sentinel, sizeof(sentinel), 0)) {
        fprintf(stderr, "Could not get PsActiveProcessHead!\n");
        return;
    }
    PTR cur_entry = sentinel;
    do {
        // Read the current list entry Flink pointer.
        if (-1 == panda_virtual_memory_read(cpu, cur_entry,
                                            (uint8_t *)&cur_entry,
                                            sizeof(cur_entry))) {
            fprintf(stderr, "Error reading process list entry!\n");
            break;
        }


        // If we've reached the sentinel, we're done.
        if (cur_entry == sentinel) {
            break;
        }

        // We've found the procss, if this is the first one go ahead and create
        // the array.
        OsiProc cur_proc;
        if (*out == NULL) {
            *out = g_array_sized_new(false, false, sizeof(cur_proc), 128);
            g_array_set_clear_func(*out, (GDestroyNotify)free_osiproc_contents);
        }
        PTR cur_eproc = cur_entry - eproc_links_off;
        fill_osiproc(cpu, &cur_proc, cur_eproc);
        g_array_append_val(*out, cur_proc);
    } while (true);
}

void on_get_current_thread(CPUState *cpu, OsiThread **out) {
    // Get current process.
    OsiProc *p = NULL;
    on_get_current_process(cpu, &p);
    if (NULL == p) {
        goto error;
    }

    OsiThread tmp;
    tmp.pid = p->pid;
    free_osiproc(p);

    PTR ethread;
    if (-1 == panda_virtual_memory_read(cpu, get_kpcr(cpu) + KPCR_CURTHREAD_OFF,
                                        (uint8_t *)&ethread, sizeof(ethread))) {
        goto error;
    }

    // Cid contains thread ID
    if (-1 == panda_virtual_memory_read(
                  cpu, ethread + kthread_cid_off + CLIENT_ID_UNIQUE_THREAD,
                  (uint8_t *)&tmp.tid, sizeof(tmp.tid))) {
        goto error;
    }

    if (NULL == *out) {
        *out = (OsiThread *)g_malloc(sizeof(**out));
    }

    **out = tmp;
error:
    return;
}

/**
 * @brief PPP callback to retrieve the process pid from a handle.
 */
void on_get_process_pid(CPUState *cpu, const OsiProcHandle *h, target_pid_t *pid) {
	if (h->taskd == (intptr_t)(NULL) || h->taskd == (target_ptr_t)-1) {
		*pid = (target_pid_t)-1;
	} else {
		*pid = get_pid(cpu, h->taskd);
	}
}

/**
 * @brief PPP callback to retrieve the process parent pid from a handle.
 */
void on_get_process_ppid(CPUState *cpu, const OsiProcHandle *h, target_pid_t *ppid) {
	if (h->taskd == (intptr_t)(NULL) || h->taskd == (target_ptr_t)-1) {
		*ppid = (target_pid_t)-1;
	} else {
		*ppid = get_ppid(cpu, h->taskd);
	}
}

uint32_t get_ntreadfile_esp_off(void) { return ntreadfile_esp_off; }

uint32_t get_kthread_kproc_off(void) { return kthread_kproc_off; }

uint32_t get_eproc_pid_off(void) { return eproc_pid_off; }

uint32_t get_eproc_name_off(void) { return eproc_name_off; }

uint32_t get_eproc_objtable_off(void) { return eproc_objtable_off; }

uint32_t get_obj_type_offset(void) { return obj_type_offset; }

uint32_t get_pid(CPUState *cpu, PTR eproc) {
    uint32_t pid;
    if(-1 == panda_virtual_memory_rw(cpu, eproc+eproc_pid_off, (uint8_t *)&pid, 4, false)) return 0;
    return pid;
}

PTR get_ppid(CPUState *cpu, PTR eproc) {
    PTR ppid;
    if(-1 == panda_virtual_memory_rw(cpu, eproc+eproc_ppid_off, (uint8_t *)&ppid, sizeof(PTR), false)) return 0;
    return ppid;
}

PTR get_dtb(CPUState *cpu, PTR eproc) {
    PTR dtb = 0;
    assert(!panda_virtual_memory_rw(cpu, eproc+EPROC_DTB_OFF, (uint8_t *)&dtb, sizeof(PTR), false));
    assert(dtb);
    return dtb;
}


void get_procname(CPUState *cpu, PTR eproc, char **name) {
    assert(name);
    *name = (char *)g_malloc(17);
    assert(*name);
    assert(!panda_virtual_memory_rw(cpu, eproc+eproc_name_off, (uint8_t *)*name, 16, false));
    (*name)[16] = '\0';
}

char *get_cwd(CPUState *cpu)
{
    PTR eproc = get_current_proc(cpu);

    // Get pointer to PEB
    target_ulong ppeb = 0x0;
    assert(!panda_virtual_memory_read(cpu, eproc + eproc_ppeb_off,
                                      (uint8_t *)&ppeb, sizeof(ppeb)));
    // Get pointer to PROCESS_PARAMETERS
    target_ulong pprocess_params = 0x0;
    assert(!panda_virtual_memory_read(cpu, ppeb + PROCESS_PARAMETERS_OFF,
                                      (uint8_t *)&pprocess_params,
                                      sizeof(pprocess_params)));

    // Get the work dir handle
    uint32_t cwd_handle = 0x0;
    assert(!panda_virtual_memory_read(cpu, pprocess_params + 0x2C,
                                      (uint8_t *)&cwd_handle,
                                      sizeof(cwd_handle)));

    char *cwd_handle_name = get_handle_name(cpu, eproc, cwd_handle);

    return cwd_handle_name;
}

bool is_valid_process(CPUState *cpu, PTR eproc) {
    uint8_t type;
    uint8_t size;

    if(eproc == 0) return false;

    if(-1 == panda_virtual_memory_rw(cpu, eproc+EPROC_TYPE_OFF, (uint8_t *)&type, 1, false)) return false;
    if(-1 == panda_virtual_memory_rw(cpu, eproc+EPROC_SIZE_OFF, (uint8_t *)&size, 1, false)) return false;

    return type == EPROC_TYPE && size == eproc_size &&
        get_next_proc(cpu, eproc);
}


uint32_t get_current_proc(CPUState *cpu) {
    PTR thread, proc;
    PTR kpcr = get_kpcr(cpu);

    // Read KPCR->CurrentThread->Process
    if (-1 == panda_virtual_memory_rw(cpu, kpcr+KPCR_CURTHREAD_OFF, (uint8_t *)&thread, sizeof(PTR), false)) return 0;
    if (-1 == panda_virtual_memory_rw(cpu, thread+get_kthread_kproc_off(), (uint8_t *)&proc, sizeof(PTR), false)) return 0;

    // Sometimes, proc == 0 here.  Is there a better way to do this?

    return is_valid_process(cpu, proc) ? proc : 0;
}

// Process introspection
PTR get_next_proc(CPUState *cpu, PTR eproc) {
    PTR next;
    if (-1 == panda_virtual_memory_rw(cpu, eproc+eproc_links_off, (uint8_t *)&next, sizeof(PTR), false))
        return 0;
    next -= eproc_links_off;
    return next;
}



// Win7 Obj Type Indices
/*
typedef enum {
    OBJ_TYPE_Type = 2,
    OBJ_TYPE_Directory = 3,
    OBJ_TYPE_SymbolicLink = 4,
    OBJ_TYPE_Token = 5,
    OBJ_TYPE_Job = 6,
    OBJ_TYPE_Process = 7,
    OBJ_TYPE_Thread = 8,
    OBJ_TYPE_UserApcReserve = 9,
    OBJ_TYPE_IoCompletionReserve = 10,
    OBJ_TYPE_DebugObject = 11,
    OBJ_TYPE_Event = 12,
    OBJ_TYPE_EventPair = 13,
    OBJ_TYPE_Mutant = 14,
    OBJ_TYPE_Callback = 15,
    OBJ_TYPE_Semaphore = 16,
    OBJ_TYPE_Timer = 17,
    OBJ_TYPE_Profile = 18,
    OBJ_TYPE_KeyedEvent = 19,
    OBJ_TYPE_WindowStation = 20,
    OBJ_TYPE_Desktop = 21,
    OBJ_TYPE_TpWorkerFactory = 22,
    OBJ_TYPE_Adapter = 23,
    OBJ_TYPE_Controller = 24,
    OBJ_TYPE_Device = 25,
    OBJ_TYPE_Driver = 26,
    OBJ_TYPE_IoCompletion = 27,
    OBJ_TYPE_File = 28,
    OBJ_TYPE_TmTm = 29,
    OBJ_TYPE_TmTx = 30,
    OBJ_TYPE_TmRm = 31,
    OBJ_TYPE_TmEn = 32,
    OBJ_TYPE_Section = 33,
    OBJ_TYPE_Session = 34,
    OBJ_TYPE_Key = 35,
    OBJ_TYPE_ALPCPort = 36,
    OBJ_TYPE_PowerRequest = 37,
    OBJ_TYPE_WmiGuid = 38,
    OBJ_TYPE_EtwRegistration = 39,
    OBJ_TYPE_EtwConsumer = 40,
    OBJ_TYPE_FilterConnectionPort = 41,
    OBJ_TYPE_FilterCommunicationPort = 42,
    OBJ_TYPE_PcwObject = 43
} OBJ_TYPES;
*/


uint32_t handle_table_code(CPUState *cpu, uint32_t table_vaddr) {
    uint32_t tableCode;
    // HANDLE_TABLE.TableCode is offest 0
    assert(!panda_virtual_memory_rw(cpu, table_vaddr, (uint8_t *)&tableCode, 4, false));
    return (tableCode & TABLE_MASK);
}


uint32_t handle_table_L1_addr(CPUState *cpu, uint32_t table_vaddr, uint32_t entry_num) {
    return table_vaddr + ADDR_SIZE * entry_num;
}


uint32_t handle_table_L2_addr(uint32_t L1_table, uint32_t L2) {
    if (L1_table != 0x0) {
        uint32_t L2_entry = L1_table + ADDR_SIZE * L2;
        return L2_entry;
    }
    return 0;
}


uint32_t handle_table_L1_entry(CPUState *cpu, uint32_t table_vaddr, uint32_t entry_num) {
    return (handle_table_code(cpu, table_vaddr) +
            HANDLE_TABLE_ENTRY_SIZE * entry_num);
}


uint32_t handle_table_L2_entry(uint32_t table_vaddr, uint32_t L1_table, uint32_t L2) {
    if (L1_table == 0) return 0;
    return L1_table + HANDLE_TABLE_ENTRY_SIZE * L2;
}


uint32_t handle_table_L3_entry(uint32_t table_vaddr, uint32_t L2_table, uint32_t L3) {
    if (L2_table == 0) return 0;
    return L2_table + HANDLE_TABLE_ENTRY_SIZE * L3;
}

uint32_t get_eproc_peb_off(void) {
    return eproc_ppeb_off;
}



// Module stuff
const char *get_mod_basename(CPUState *cpu, PTR mod) {
    return get_unicode_str(cpu, mod+LDR_BASENAME_OFF);
}

const char *get_mod_filename(CPUState *cpu, PTR mod) {
    return get_unicode_str(cpu, mod+LDR_FILENAME_OFF);
}

PTR get_mod_base(CPUState *cpu, PTR mod) {
    PTR base;
    assert(!panda_virtual_memory_rw(cpu, mod+LDR_BASE_OFF, (uint8_t *)&base, sizeof(PTR), false));
    return base;
}

PTR get_mod_size(CPUState *cpu, PTR mod) {
    uint32_t size;
    assert(!panda_virtual_memory_rw(cpu, mod+LDR_SIZE_OFF, (uint8_t *)&size, sizeof(uint32_t), false));
    return size;
}

PTR get_next_mod(CPUState *cpu, PTR mod) {
    PTR next;
    if (-1 == panda_virtual_memory_rw(cpu, mod+LDR_LOAD_LINKS_OFF, (uint8_t *)&next, sizeof(PTR), false))
        return 0;
    next -= LDR_LOAD_LINKS_OFF;
    return next;
}

char *read_unicode_string(CPUState *cpu, uint32_t pUstr)
{
    return get_unicode_str(cpu, pUstr);
}

char *get_objname(CPUState *cpu, uint32_t obj) {
  uint32_t pObjectName;
  assert(-1 != panda_virtual_memory_rw(cpu, obj+OBJNAME_OFF, (uint8_t *)&pObjectName, sizeof(pObjectName), false));
  return read_unicode_string(cpu, pObjectName);
}

char *get_file_obj_name(CPUState *cpu, uint32_t fobj) {
    return read_unicode_string(cpu, fobj + FILE_OBJECT_NAME_OFF);
}

int64_t get_file_obj_pos(CPUState *cpu, uint32_t fobj) {
    int64_t file_pos;
	if (-1 == panda_virtual_memory_rw(cpu, fobj+FILE_OBJECT_POS_OFF, (uint8_t *)&file_pos, sizeof(file_pos), false)) {
	  return -1;
	} else {
	  return file_pos;
	}
}

char *get_handle_object_name(CPUState *cpu, HandleObject *ho) {
    char *name;
    if (ho == NULL) {
        name = g_strdup("unknown");
    } else if(ho->objType == obj_type_file) {
        name = get_file_obj_name(cpu, ho->pObj);
    } else if(ho->objType == obj_type_key) {
        name = g_strdup_printf("_CM_KEY_BODY@%08x", ho->pObj);
    } else if(ho->objType == obj_type_process) {
        get_procname(cpu, ho->pObj, &name);
    } else {
        name=g_strdup_printf("unknown object type %d", ho->objType);
    }
    assert(name);
    return name;
}


char *get_handle_name(CPUState *cpu, PTR eproc, uint32_t handle) {
    HandleObject *ho = get_handle_object(cpu, eproc, handle);
    return get_handle_object_name(cpu, ho);
}

int64_t get_file_handle_pos(CPUState *cpu, PTR eproc, uint32_t handle) {
    HandleObject *ho = get_handle_object(cpu, eproc, handle);
    if (!ho) {
        return -1;
    } else {
        return get_file_obj_pos(cpu, ho->pObj);
    }
}

void fill_osiproc(CPUState *cpu, OsiProc *p, PTR eproc) {
    p->taskd = eproc;
    get_procname(cpu, eproc, &p->name);
    p->asid = get_dtb(cpu, eproc);
    p->pages = NULL;
    p->pid = get_pid(cpu, eproc);
    p->ppid = get_ppid(cpu, eproc);
}

void fill_osiprochandle(CPUState *cpu, OsiProcHandle *h, PTR eproc) {
    h->taskd = eproc;
    h->asid = get_dtb(cpu, eproc);
}

void fill_osimod(CPUState *cpu, OsiModule *m, PTR mod, bool ignore_basename) {
    m->modd = mod;
    m->file = (char *)get_mod_filename(cpu, mod);
    m->base = get_mod_base(cpu, mod);
    m->size = get_mod_size(cpu, mod);
    m->name = ignore_basename ? g_strdup("-") : (char *)get_mod_basename(cpu, mod);
    assert(m->name);
}
#endif


bool init_plugin(void *self) {
#ifdef TARGET_I386
    // this stuff only currently works for win7 or win2000, 32-bit
    assert (panda_os_familyno == OS_WINDOWS);
    assert (panda_os_bits == 32);
    assert (panda_os_variant);

    if(0 == strcmp(panda_os_variant, "7")) {
        kthread_kproc_off=0x150;
        kthread_cid_off = 0x22c;
        eproc_pid_off=0x0b4;
        eproc_ppid_off=0x140;
        eproc_name_off=0x16c;
        eproc_objtable_off=0xf4;
        eproc_ppeb_off = 0x1a8;
        obj_type_file = 28;
        obj_type_key = 35;
        obj_type_process = 7;
        obj_type_offset = 0xc;
        eproc_size = 0x26;
        eproc_links_off = 0x0b8;
        ntreadfile_esp_off = 0;
        panda_require("win7x86intro");
        assert(init_win7x86intro_api());
        get_kpcr = get_win7_kpcr;
        get_handle_object = get_win7_handle_object;
        get_kddebugger_data = get_win7_kdbg;
    } else if (0 == strcmp(panda_os_variant, "2000")) {
        kthread_kproc_off = 0x22c;
        kthread_cid_off = 0x1e0;
        eproc_pid_off=0x09c;
        eproc_ppid_off=0x1c8;
        eproc_name_off=0x1fc;
        eproc_objtable_off=0x128;
        eproc_ppeb_off = 0x1b0;
        obj_type_file = 0x05;
        obj_type_key = 0x32;
        obj_type_process = 0x03;
        obj_type_offset = 0x18;
        eproc_size = 0x1b;
        eproc_links_off = 0x0a0;
        ntreadfile_esp_off = 0x24;
        panda_require("win2000x86intro");
        assert(init_win2000x86intro_api());
        get_kpcr = get_win2000_kpcr;
        get_handle_object = get_win2000_handle_object;
        get_kddebugger_data = get_win2000_kddebugger_data;
    } else if (0 == strcmp(panda_os_variant, "xpsp3")) {
        kthread_kproc_off = 0x044;
        kthread_cid_off = 0x1ec;
        eproc_pid_off = 0x084;
        eproc_ppid_off = 0x14c;
        eproc_name_off = 0x174;
        eproc_objtable_off = 0x0c4;
        eproc_ppeb_off = 0x1b0;
        obj_type_file = 28;
        obj_type_key = 20;
        obj_type_process = 5;
        obj_type_offset = 0x8;
        eproc_size = 0x1b; // why???
        eproc_links_off = 0x088;
        ntreadfile_esp_off = 0;
        panda_require("winxpx86intro");
        assert(init_winxpx86intro_api());
        get_kpcr = get_winxp_kpcr;
        get_handle_object = get_winxp_handle_object;
        get_kddebugger_data = get_winxp_kdbg;
    } else {
        fprintf(stderr, "Plugin is not supported for this windows "
            "version (%s).\n", panda_os_variant);
    }

    PPP_REG_CB("osi", on_get_current_process, on_get_current_process);
    PPP_REG_CB("osi", on_get_current_process_handle, on_get_current_process_handle);
    PPP_REG_CB("osi", on_get_processes, on_get_processes);
    PPP_REG_CB("osi", on_get_current_thread, on_get_current_thread);
    PPP_REG_CB("osi", on_get_process_pid, on_get_process_pid);
    PPP_REG_CB("osi", on_get_process_ppid, on_get_process_ppid);
    PPP_REG_CB("osi", on_get_libraries, on_get_libraries);
    PPP_REG_CB("osi", on_get_modules, on_get_modules);

    return true;
#else
    fprintf(stderr, "Plugin is not supported on this platform.\n");
    return false;
#endif

}

void uninit_plugin(void *self) {
    printf("Unloading wintrospection plugin\n");
}

/* vim: set tabstop=4 softtabstop=4 expandtab: */
