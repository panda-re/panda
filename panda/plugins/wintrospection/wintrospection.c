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

#include "glib.h"

bool init_plugin(void *);
void uninit_plugin(void *);

// this stuff only makes sense for win x86 32-bit
#ifdef TARGET_I386

// Constants that are the same in all supported versions of windows
// Currently just Windows 7 and Windows 2000
#define KPCR_CURTHREAD_OFF   0x124 // _KPCR.PrcbData.CurrentThread
#define EPROC_DTB_OFF        0x018 // _EPROCESS.Pcb.DirectoryTableBase
#define EPROC_TYPE_OFF       0x000 // _EPROCESS.Pcb.Header.Type
#define EPROC_SIZE_OFF       0x002 // _EPROCESS.Pcb.Header.Size
#define EPROC_TYPE           0x003 // Value of Type
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

// "Constants" specific to the guest operating system.
// These are initialized in the init_plugin function.
static uint32_t kthread_kproc_off;  // _KTHREAD.Process
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

void on_get_current_process(CPUState *cpu, OsiProc **out_p) {
    PTR eproc = get_current_proc(cpu);
    if(eproc) {
        OsiProc *p = (OsiProc *)g_malloc(sizeof(OsiProc));
        fill_osiproc(cpu, p, eproc);
        *out_p = p;
    } else {
        *out_p = NULL;
    }
}

void on_get_processes(CPUState *cpu, GArray **out) {
    OsiProc p;
    PTR first, current;

    first = get_current_proc(cpu);
    current = first;
    if (first == (uintptr_t)NULL) {
        goto error;
    }
    if (get_pid(cpu, first) == 0) {
        // idle proc - don't try
        goto error;
    }

    g_array_free(*out, true);
    // g_array_sized_new() args: zero_term, clear, element_sz, reserved_sz
    *out = g_array_sized_new(false, false, sizeof(OsiProc), 128);
    g_array_set_clear_func(*out, (GDestroyNotify)free_osiproc);

    do {
        // One of these will be the loop head,
        // which we don't want to include
        if (is_valid_process(cpu, current)) {
            memset(&p, 0, sizeof(OsiProc));
            fill_osiproc(cpu, &p, current);
            g_array_append_val(*out, p);
        }
        current = get_next_proc(cpu, current);
    } while (current != (uintptr_t)NULL && current != first);

    return;

error:
    g_array_free(*out, true);  // safe even when *out == NULL
    *out = NULL;
    return;
}

void on_get_current_thread(CPUState *cpu, OsiThread **out) {
    OsiProc *p = NULL;
    CPUArchState *env = (CPUArchState *)first_cpu->env_ptr;

    on_get_current_process(cpu, &p);
    if (p == NULL) {
        goto error;
    }
    if (*out == NULL) {
        *out = (OsiThread *)g_malloc(sizeof(OsiThread));
    }

    // Get the process id.
    OsiThread *t = *out;
    t->pid = p->pid;
    free_osiproc(p);

    // Get current thread ID from thread information block.
    target_ulong ptib;
    panda_virtual_memory_read(first_cpu, env->segs[R_FS].base + 0x18,
                              (uint8_t *)&ptib, sizeof(ptib));
    panda_virtual_memory_read(first_cpu, ptib + 0x24, (uint8_t *)&t->tid,
                              sizeof(t->tid));
    return;

error:
    *out = NULL;
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
    } else if (0 == strcmp(panda_os_variant, "2000")) {
        kthread_kproc_off=0x22c;
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
    } else {
        fprintf(stderr, "Plugin is not supported for this windows "
            "version (%s).\n", panda_os_variant);
    }

    PPP_REG_CB("osi", on_get_current_process, on_get_current_process);
    PPP_REG_CB("osi", on_get_processes, on_get_processes);
    PPP_REG_CB("osi", on_get_current_thread, on_get_current_thread);

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
