/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Ben Dumas              benjamin.dumas@ll.mit.edu
 *  Nick Gillum            nicholas.gillum@ll.mit.edu
 *  Lisa Baer              lisa.baer@ll.mit.edu
 *  Luke Craig             luke.craig@ll.mit.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <offset/i_t.h>
#include <offset/offset.h>

#include <osi/windows/iterator.h>
#include <osi/windows/manager.h>
#include <osi/windows/ustring.h>
#include <osi/windows/wintrospection.h>

#include <iconv.h>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "glib.h"

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include "panda/tcg-utils.h"

#include "../osi/osi_types.h"
#include "../osi/osi_ext.h"
#include "../osi/os_intro.h"
#include <hooks/hooks_int_fns.h>

#include "pandamemory.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
void (*hooks_add_hook)(struct hook*);
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);

int64_t get_file_handle_pos(CPUState *cpu, uint64_t handle);
char *get_cwd(CPUState *cpu);
char *get_handle_name(CPUState *cpu, uint64_t handle);
void *get_windows_process_manager(void);
}

void on_get_current_thread(CPUState *cpu, OsiThread *out);
void on_get_process_pid(CPUState *cpu, const OsiProcHandle *h,
                        target_pid_t *pid);
void on_get_current_process_handle(CPUState *cpu, OsiProcHandle **out);
void on_get_process_handles(CPUState *cpu, GArray **out);
void on_get_process_ppid(CPUState *cpu, const OsiProcHandle *h,
                         target_pid_t *ppid);
void on_get_current_process(CPUState *cpu, OsiProc **out);
void on_get_process(CPUState *cpu, const OsiProcHandle *h, OsiProc **out);
void on_get_processes(CPUState *cpu, GArray **out);
void on_get_modules(CPUState *cpu, GArray **out);
void on_get_mappings(CPUState *cpu, OsiProc *p, GArray **out);
void on_get_mapping_by_addr(CPUState *cpu, OsiProc *p, const target_ptr_t addr, OsiModule **out);
void on_get_mapping_base_address_by_name(CPUState *cpu, OsiProc *p, const char *name, target_ptr_t *base_address);
void on_has_mapping_prefix(CPUState *cpu, OsiProc *p, const char *prefix, bool *found);

void initialize_introspection(CPUState *cpu);
void initialize_swapcontext_task_change(CPUState *cpu);
void task_change(CPUState *cpu);

std::unique_ptr<WindowsKernelManager> g_kernel_manager;
std::unique_ptr<WindowsProcessManager> g_process_manager;

bool g_initialized_kernel;
uint64_t swapcontext_address;

// last process address seen
static uint64_t last_seen_paddr = 0;

// last thread id seen
static uint64_t last_seen_tid = std::numeric_limits<uint64_t>::max();

// true when using asid change heuristic to detect task changes
static bool using_asid_change_heuristic = true;

// globals for toggling callbacks
void* self = NULL;
panda_cb pcb_asid;
panda_cb pcb_startblock;

static std::map<std::string, uint64_t> system_asid_lookup = {
  {"windows-32-2000", 0x30000},
  {"windows-32-xpsp2", 0x39000},
  {"windows-32-xpsp3", 0x39000},
  {"windows-32-7sp0", 0x185000},
  {"windows-64-7sp0", 0x187000},
  {"windows-32-7sp1", 0x185000},
  {"windows-64-7sp1", 0x187000},
};

void *get_windows_process_manager(void) {
  return g_process_manager.get();
}

/* ******************************************************************
 Helpers
****************************************************************** */
void fill_process(OsiProc *p, WindowsProcess *win_proc) {
  p->taskd = process_get_eprocess(win_proc);
  p->asid = process_get_asid(win_proc);
  p->pid = process_get_pid(win_proc);
  p->ppid = process_get_ppid(win_proc);
  p->pages = NULL;

  p->name = (char *)g_malloc(17);
  strncpy(p->name, process_get_shortname(win_proc), 17);
}

void fill_module(OsiModule *m, struct WindowsModuleEntry *win_mod) {
  m->modd = module_entry_get_module_entry(win_mod);
  m->size = module_entry_get_modulesize(win_mod);
  m->base = module_entry_get_base_address(win_mod);
  m->file = strdup(module_entry_get_dllpath(win_mod));
  m->name = strdup(module_entry_get_dllname(win_mod));
}

std::string get_key_name(uint64_t ptr) {
  if (strncmp(panda_os_name, "windows-32-2000", 15) == 0) {
    // just keep previous functionality for windows 2k,
    // as we couldn't verify the fancy functionality works
    return std::string("_CM_KEY_BODY@0x") + std::to_string(ptr);
  }

  auto object = g_process_manager->get_type(ptr, "_CM_KEY_BODY");

  osi::i_t nameblock;
  uint8_t compressed;
  uint16_t size;

  std::vector<std::string> keyname;

  auto kcb = object("KeyControlBlock");
  while (kcb.get_address()) {
    nameblock = kcb("NameBlock");
    compressed = nameblock["Compressed"].get8();
    size = nameblock["NameLength"].get16();

    if (compressed) {
      char *temp = new char[size + 1]{'\0'};
      nameblock["Name"].getx(*temp, size);

      size_t total = strnlen(temp, size);
      if (total == size) {
        temp[size] = '\0';
      }

      for (size_t idx = 0; idx < total; idx++) {
        if (!isprint(temp[idx])) {
          temp[idx] = '?';
        }
      }

      keyname.push_back(std::string(temp, total));
      delete temp;
    } else {
      auto raw_name =
          osi::ustring(nameblock["Name"].set_type("_UNICODE_STRING"));
      keyname.push_back(raw_name.as_utf8());
    }
    kcb = kcb("ParentKcb");
  }

  std::string full_key;
  for (auto it = keyname.rbegin(); it != keyname.rend(); it++) {
    full_key += "\\" + *it;
  }

  return full_key;
}

std::string extract_handle_name(struct WindowsHandleObject *handle) {
  auto ptr = handle_get_pointer(handle);
  if (!ptr) {
    return "unknown";
  }

  std::stringstream ss;

  const char *type_name = handle_get_typename(handle);
  if (strcmp(type_name, "Key") == 0) {
    ss << get_key_name(ptr);
  } else if (strcmp(type_name, "File") == 0) {
    auto file = g_process_manager->get_type(ptr, "_FILE_OBJECT");
    osi::ustring uname(file["FileName"]);
    ss << uname.as_utf8();
  } else if (strcmp(type_name, "Process") == 0) {
    struct WindowsProcess *p =
        create_process(g_kernel_manager->get_kernel_object(), ptr);
    ss << process_get_shortname(p);
    free_process(p);
  } else {
    ss << "unknown object type " << handle_get_type(handle);
  }

  return ss.str();
}

/* ******************************************************************
 Our Callbacks
****************************************************************** */

int64_t get_file_handle_pos(CPUState *cpu, uint64_t handle) {
  if (!g_initialized_kernel) {
    initialize_introspection(cpu);
  }

  auto kernel = g_kernel_manager->get_kernel_object();
  WindowsHandleObject *h = resolve_handle(kernel, handle);

  uint64_t ptr;
  int64_t file_pos = -1;
  if (h != nullptr && (ptr = handle_get_pointer(h))) {
    try {
      auto file = g_process_manager->get_type(ptr, "_FILE_OBJECT");
      file_pos = file["CurrentByteOffset"].get64();
    } catch (std::runtime_error const &) {
      // runtime_error is raised when a virtual memory read fails
      // it's the equiv of (-1 == panda_virtual_memory_rw(...))
    }
  }

  free_handle(h);
  return file_pos;
}

char *get_cwd(CPUState *cpu) {
  if (!g_initialized_kernel) {
    initialize_introspection(cpu);
  }

  osi::i_t eproc = g_process_manager->get_process();

  bool wow = false;
  if (panda_os_bits == 64 && eproc["Wow64Process"].getu())
    wow = true;

  osi::i_t peb;
  if (wow) {
    peb = eproc("Wow64Process").set_type("_PEB32");
  } else {
    peb = eproc("Peb");
  }

  osi::i_t params;
  if (wow) {
    params = g_process_manager->get_type(peb["ProcessParameters"].get32(),
                                         "_RTL_USER_PROCESS_PARAMETERS");
  } else {
    params = peb("ProcessParameters");
  }

  auto dospath = osi::ustring(params["CurrentDirectory"]["DosPath"]);
  std::string path = dospath.as_utf8();
  return strdup(path.c_str());
}

char *get_handle_name(CPUState *cpu, uint64_t handle) {
  if (!g_initialized_kernel) {
    initialize_introspection(cpu);
  }

  auto kernel = g_kernel_manager->get_kernel_object();
  WindowsHandleObject *h = resolve_handle(kernel, handle);
  if (!h)
    return strdup("unknown");

  auto tmp = extract_handle_name(h);
  char *name = strdup(tmp.c_str());

  free_handle(h);
  return name;
}

// fill in thread id and process id into OsiThread structure
// when using asid change heuristic, update g_process_manager if process id
// changed since the last time fill_thread was called
static inline void fill_thread(CPUState *cpu, OsiThread *t) {
  auto kernel = g_kernel_manager->get_kernel_object();
  uint64_t tid = kosi_get_current_tid(kernel);

  // if the thread id changed, process may also have changed
  if(using_asid_change_heuristic && (tid != last_seen_tid)) {
    last_seen_tid = tid;
    uint64_t paddr = kosi_get_current_process_address(kernel);
    if(paddr != last_seen_paddr) {
      last_seen_paddr = paddr;
      g_process_manager.reset(new WindowsProcessManager());
      g_process_manager->initialize(kernel, paddr);
      notify_task_change(cpu);
    }
  }

  auto proc = g_process_manager->get_process_object();

  if(t) {
    t->pid = proc->pid;
    t->tid = tid;
  }
}

/* ******************************************************************
 PPP Callbacks
****************************************************************** */

void on_get_current_thread(CPUState *cpu, OsiThread **out) {
  if (!g_initialized_kernel) {
    initialize_introspection(cpu);
  }

  OsiThread *t = (OsiThread *)g_malloc(sizeof(OsiThread));
  fill_thread(cpu, t);
  *out = t;
}

void on_get_process_pid(CPUState *cpu, const OsiProcHandle *h,
                        target_pid_t *pid) {
  if (!g_initialized_kernel) {
    initialize_introspection(cpu);
  }

  if (h->taskd == (intptr_t)(NULL) || h->taskd == (target_ptr_t)-1) {
    *pid = (target_pid_t)-1;
  } else {
    if(using_asid_change_heuristic) {
        // process may have changed
        fill_thread(cpu, NULL);
    }
    *pid = g_process_manager->get_process_object()->pid;
  }
}

void on_get_current_process_handle(CPUState *cpu, OsiProcHandle **out) {
  if (!g_initialized_kernel) {
    initialize_introspection(cpu);
  }

  OsiProcHandle *p = (OsiProcHandle *)g_malloc(sizeof(OsiProcHandle));

  if(using_asid_change_heuristic) {
    // process may have changed
    fill_thread(cpu, NULL);
  }

  auto process = g_process_manager->get_process_object();
  p->taskd = process->eprocess_address;
  p->asid = process->vmem->get_asid();

  *out = p;
}

void on_get_process_handles(CPUState *cpu, GArray **out) {
  if (!g_initialized_kernel) {
    initialize_introspection(cpu);
  }

  if (*out == NULL) {
    *out = g_array_sized_new(false, false, sizeof(OsiProcHandle), 128);
    g_array_set_clear_func(*out, (GDestroyNotify)free_osiprochandle_contents);
  }

  auto kernel = g_kernel_manager->get_kernel_object();

  struct WindowsProcessList *plist = get_process_list(kernel);
  struct WindowsProcess *process;
  while ((process = process_list_next(plist)) != nullptr) {
    OsiProcHandle cur_handle;
    cur_handle.taskd = process_get_eprocess(process);
    cur_handle.asid = process_get_asid(process);
    g_array_append_val(*out, cur_handle);

    free_process(process);
  }
  free_process_list(plist);
}

void on_get_process_ppid(CPUState *cpu, const OsiProcHandle *h,
                         target_pid_t *ppid) {
  if (!g_initialized_kernel) {
    initialize_introspection(cpu);
  }

  if (h->taskd == (intptr_t)(NULL) || h->taskd == (target_ptr_t)-1) {
    *ppid = (target_pid_t)-1;
  } else {
    auto kernel = g_kernel_manager->get_kernel_object();
    auto process = kosi_get_current_process(kernel);
    *ppid = process_get_ppid(process);
    free_process(process);
  }
}

void on_get_current_process(CPUState *cpu, OsiProc **out) {
  if (!g_initialized_kernel) {
    initialize_introspection(cpu);
  }

  OsiProc *p = (OsiProc *)g_malloc(sizeof(OsiProc));

  if(using_asid_change_heuristic) {
    // process may have changed
    fill_thread(cpu, NULL);
  }

  auto proc = g_process_manager->get_process_object();
  if (proc->eprocess_address == 0) {
    *out = NULL;
    return;
  }

  auto kernel = g_kernel_manager->get_kernel_object();
  WindowsProcess *process = create_process(kernel, proc->eprocess_address);
  fill_process(p, process);
  free_process(process);

  *out = p;
}

void on_get_process(CPUState *cpu, const OsiProcHandle *h, OsiProc **out) {
  if (!g_initialized_kernel) {
    initialize_introspection(cpu);
  }

  OsiProc *p = NULL;
  if (h != NULL && h->taskd != (target_ptr_t)NULL) {
    p = (OsiProc *)g_malloc(sizeof(OsiProc));

    auto kernel = g_kernel_manager->get_kernel_object();
    auto proc = create_process(kernel, h->taskd);
    fill_process(p, proc);
    free_process(proc);
  }
  *out = p;
}

void on_get_processes(CPUState *cpu, GArray **out) {
  if (!g_initialized_kernel) {
    initialize_introspection(cpu);
  }

  if (*out == NULL) {
    *out = g_array_sized_new(false, false, sizeof(OsiProc), 128);
    g_array_set_clear_func(*out, (GDestroyNotify)free_osiproc_contents);
  }

  auto kernel = g_kernel_manager->get_kernel_object();

  struct WindowsProcessList *plist = get_process_list(kernel);
  struct WindowsProcess *process;
  while ((process = process_list_next(plist)) != nullptr) {
    OsiProc cur_proc;
    fill_process(&cur_proc, process);
    g_array_append_val(*out, cur_proc);

    free_process(process);
  }
  free_process_list(plist);
}

void on_get_modules(CPUState *cpu, GArray **out) {
  if (!g_initialized_kernel) {
    initialize_introspection(cpu);
  }

  if (*out == NULL) {
    // g_array_sized_new() args: zero_term, clear, element_sz, reserved_sz
    *out = g_array_sized_new(false, false, sizeof(OsiModule), 128);
    g_array_set_clear_func(*out, (GDestroyNotify)free_osimodule_contents);
  }

  auto kernel = g_kernel_manager->get_kernel_object();

  auto ldr_table = g_kernel_manager->get_type(
      kernel->details.PsLoadedModuleList, "_LDR_DATA_TABLE_ENTRY");
  osi::iterator pitr(ldr_table, "InLoadOrderLinks");
  do {
    auto entry = *pitr;

    OsiModule m;
    memset(&m, 0, sizeof(OsiModule));

    m.modd = entry.get_address();
    m.size = entry["SizeOfImage"].get32();
    m.base = entry["DllBase"].getu();

    try {
      osi::ustring dllname(entry["BaseDllName"]);
      std::string dllname_utf8 = dllname.as_utf8().c_str();
      m.name = strdup(dllname_utf8.c_str());

      osi::ustring dllpath(entry["FullDllName"]);
      std::string dllpath_utf8 = dllpath.as_utf8();
      m.file = strdup(dllpath_utf8.c_str());
    } catch (std::runtime_error const &) {
      // runtime_error is thrown when virtual memory
      // cannot read the struct attribute
      m.name = strdup("-");
      m.file = strdup("-");
    }

    g_array_append_val(*out, m);

    pitr++;
  } while (*pitr != ldr_table);
}

void on_get_mappings(CPUState *cpu, OsiProc *p, GArray **out) {
  if (!g_initialized_kernel) {
    initialize_introspection(cpu);
  }

  if (p == NULL) {
    *out = nullptr;
    return;
  }

  if (*out == NULL) {
    // g_array_sized_new() args: zero_term, clear, element_sz, reserved_sz
    *out = g_array_sized_new(false, false, sizeof(OsiModule), 128);
    g_array_set_clear_func(*out, (GDestroyNotify)free_osimodule_contents);
  }

  auto kernel = g_kernel_manager->get_kernel_object();

  auto proc = create_process(kernel, p->taskd);
  struct WindowsModuleList *mlist =
      get_module_list(kernel, p->taskd, process_is_wow64(proc));
  free_process(proc);

  if (mlist) {
    struct WindowsModuleEntry *mentry;
    while ((mentry = module_list_next(mlist)) != nullptr) {
      OsiModule m;
      memset(&m, 0, sizeof(OsiModule));
      fill_module(&m, mentry);
      g_array_append_val(*out, m);

      free_module_entry(mentry);
    }
  }

  // this is guarded from nullptr, so safe here
  free_module_list(mlist);
}

void on_get_mapping_by_addr(CPUState *cpu, OsiProc *p, const target_ptr_t addr,
        OsiModule **out) {
  if (!g_initialized_kernel) {
    initialize_introspection(cpu);
  }
  
  if (p == NULL) {
    *out = nullptr;
    return;
  }

  auto kernel = g_kernel_manager->get_kernel_object();

  auto proc = create_process(kernel, p->taskd);
  auto mentry = get_module_by_addr(kernel, p->taskd, process_is_wow64(proc),
      addr);
  free_process(proc);

  if (mentry) {
    *out = (OsiModule *)g_malloc(sizeof(**out));
    fill_module(*out, mentry);
    free_module_entry(mentry);
  } else {
    *out = nullptr;
  }
}

void on_get_mapping_base_address_by_name(CPUState *cpu, OsiProc *p,
        const char *name, target_ptr_t *base_address) {
  if (!g_initialized_kernel) {
    initialize_introspection(cpu);
  }
  
  if (p == NULL) {
    *base_address = 0;
    return;
  }

  auto kernel = g_kernel_manager->get_kernel_object();

  auto proc = create_process(kernel, p->taskd);
  *base_address = static_cast<target_ptr_t>(get_module_base_address_by_name(
      kernel, p->taskd, process_is_wow64(proc), name));
  free_process(proc);
}

void on_has_mapping_prefix(CPUState *cpu, OsiProc *p, const char *prefix,
    bool *found) {
  if (!g_initialized_kernel) {
    initialize_introspection(cpu);
  }
  
  if (p == NULL) {
    *found = false;
    return;
  }

  auto kernel = g_kernel_manager->get_kernel_object();

  auto proc = create_process(kernel, p->taskd);
  *found = has_module_prefix(kernel, p->taskd, process_is_wow64(proc), prefix);
  free_process(proc);
}

/* ******************************************************************
 Initialization logic
****************************************************************** */

void task_change(CPUState *cpu) {
  if(last_seen_paddr != 0) {
    g_process_manager.reset(new WindowsProcessManager());
  }
  auto kernel = g_kernel_manager->get_kernel_object();
  last_seen_paddr = kosi_get_current_process_address(kernel);
  if(last_seen_paddr != 0) {
    g_process_manager->initialize(kernel, last_seen_paddr);
  }

  notify_task_change(cpu);
}

void start_block_exec(CPUState *cpu, TranslationBlock *tb) {
  task_change(cpu);
  panda_disable_callback(self, PANDA_CB_START_BLOCK_EXEC, pcb_startblock);
}

bool asid_changed(CPUState *cpu, target_ulong old_pgd, target_ulong new_pgd) {
  if (!g_initialized_kernel) {
    initialize_introspection(cpu);
  }

  if (old_pgd != new_pgd)
    panda_enable_callback(self, PANDA_CB_START_BLOCK_EXEC, pcb_startblock);

  return false;
}

void task_change_hook(CPUState *cpu, TranslationBlock *tb, struct hook* h){
  task_change(cpu);
}

/**
 * Get the Kernel Processor Control Region (KPCR) on a 32-bit system
 *
 * The KPCR should be accessible from FS. FS is stored at selector 0x30
 * in the Global Descriptor Table (GDT), so we look here to load it.
 * The base of this segment contains the KPCR.
 *
 */
uint64_t get_kpcr_i386(CPUState *cpu) {
#if defined(TARGET_I386)
  CPUArchState *env = (CPUArchState *)cpu->env_ptr;

  // read the FS segment descriptor from the GDT
  uint32_t e1 = 0, e2 = 0;
  panda_virtual_memory_rw(cpu, env->gdt.base + 0x30, (uint8_t *)&e1, 4, false);
  panda_virtual_memory_rw(cpu, env->gdt.base + 0x30 + 4, (uint8_t *)&e2, 4,
                          false);

  // get base address from wacky segment
  // see https://wiki.osdev.org/Global_Descriptor_Table
  // for a layout -- we need the upper 16 bits of the first word, and
  // the lowest and highest byte of the second word all together
  uint32_t addr = ((e1 >> 16) | ((e2 & 0xff) << 16) | (e2 & 0xff000000));

  return addr;
#endif
  return 0;
}

/**
 * Get the Kernel Processor Control Region (KPCR) on a 64-bit system
 *
 * The KPCR should be stored in the Model Specific Register, KernelGSBase. If
 * it is not there, then it has already been swapped into GS (with swapgs). We
 * know if a KPCR has been found, because a KPCR struct has a pointer to itself
 * at offset 0x18.
 */
uint64_t get_kpcr_amd64(CPUState *cpu) {
#if defined(TARGET_X86_64)
  CPUArchState *env = (CPUArchState *)cpu->env_ptr;

  uint64_t kpcr = env->kernelgsbase;

  auto tlib = load_type_library(panda_os_name);
  auto mr = offset_of(tlib, translate(tlib, "_KPCR"), "Self");

  // check if the SelfPcr member is a pointer to itself. if so, we found the
  // KPCR.
  uint64_t base_self;
  panda_virtual_memory_rw(cpu, kpcr + mr->offset, (uint8_t *)&base_self, 8,
                          false);
  if (kpcr != base_self) {
    // it has been swapped into GS
    kpcr = env->segs[R_GS].base;
  }

  free_member_result(mr);
  return kpcr;
#endif
  return 0;
}

bool is_windows_pae_enabled(CPUState* cpu) {
#if defined(TARGET_I386)
  // windows only uses PAE on 32-bit systems for x86
  if (panda_os_bits == 32) {
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;

    bool cr0_paging_enabled = env->cr[0] & 0x80000000;
    bool cr4_pae_enabled = env->cr[4] & 0x20;

    return cr0_paging_enabled && cr4_pae_enabled;
  }
#endif
  return false;
}

void initialize_swapcontext_task_change(CPUState *cpu){
  uint64_t swapcontext_offset = g_kernel_manager->get_swapcontext_offset();

  // we do not know exactly when a nt!SwapContext executes, and we must use the
  // ASID change heuristic.
  if (swapcontext_offset == 0x0) {
    fprintf(stderr, "Error finding nt!SwapContext. Defaulting to ASID change heuristic.\n");
    using_asid_change_heuristic = true;
    return;
  }

  GArray *mods = get_modules(cpu);
  for (int i = 0; i < mods->len; i++) {
      OsiModule *mod = &g_array_index(mods, OsiModule, i);
      if (0 == strcmp("ntoskrnl.exe", mod->name)) {
          swapcontext_address = mod->base + swapcontext_offset;
      }
  }
  if (NULL != mods) {
      g_array_free(mods, true);
  }

  if (swapcontext_address == 0x0) {
    fprintf(stderr, "Error finding ntoskrnl! Defaulting to ASID change heuristic.\n");
    using_asid_change_heuristic = true;
  } else {
    // disable ASID change heuristic
    panda_disable_callback(self, PANDA_CB_ASID_CHANGED, pcb_asid);

    // add hook for swapcontext_address
    void *hooks = panda_get_plugin_by_name("hooks");
    if (hooks == NULL){
      panda_require("hooks");
      hooks = panda_get_plugin_by_name("hooks");
    }
    hooks_add_hook = (void (*)(struct hook *))dlsym(hooks, "add_hook");

    // create hook for swapcontext_address
    struct hook h;
    h.addr = swapcontext_address;
    h.asid = 0; // match any asid
    h.cb.start_block_exec = task_change_hook;
    h.type = PANDA_CB_START_BLOCK_EXEC;
    h.enabled = true;
    h.km = MODE_ANY;
    hooks_add_hook(&h);
  }
}

void initialize_introspection(CPUState *cpu) {
  auto pmem = create_panda_physical_memory();
  if (!pmem) {
    fprintf(stderr, "Error creating physical memory interface\n");
    exit(1);
  }

  auto asid_entry = system_asid_lookup.find(std::string(panda_os_name));
  if (asid_entry == system_asid_lookup.end()) {
    fprintf(stderr, "%s is an unsupported profile\n", panda_os_name);
    exit(2);
  }

  auto kpcr = (panda_os_bits == 64) ? get_kpcr_amd64(cpu) : get_kpcr_i386(cpu);
  auto width = (panda_os_bits == 64) ? 8 : 4;

  auto success = g_kernel_manager->initialize(pmem, width, asid_entry->second,
                                              kpcr, is_windows_pae_enabled(cpu));
  if (!success) {
    fprintf(stderr, "Error initializing kernel manager\n");
    exit(3);
  }
  g_initialized_kernel = true;

  g_process_manager =
      std::unique_ptr<WindowsProcessManager>(new WindowsProcessManager());
  task_change(cpu);

  if (!using_asid_change_heuristic) {
    initialize_swapcontext_task_change(cpu);
  }
}

bool init_plugin(void *_self) {
#if defined(TARGET_I386) // only supports i386 and x86_64
  panda_require("osi");
  assert(init_osi_api());
  self = _self;

  // get arguments to this plugin
  panda_arg_list *args = panda_get_args("wintrospection");
  using_asid_change_heuristic = panda_parse_bool_opt(args, "asid_change_heuristic", "enable asid change heuristic");
  
  // Hooking SwapContext on windows 2000 doesn't seem to be enough to detect
  // all tasks changes, fallback to ASID change heuristic for now.
  if (strncmp(panda_os_name, "windows-32-2000", 15) == 0 && !using_asid_change_heuristic) {
    fprintf(stderr, "Warning: ASID change heuristic is required for windows 2000. Automatically enabling.\n");
    using_asid_change_heuristic = true;
  }
  
  pcb_startblock.start_block_exec = start_block_exec;
  panda_register_callback(self, PANDA_CB_START_BLOCK_EXEC, pcb_startblock);
  panda_disable_callback(self, PANDA_CB_START_BLOCK_EXEC, pcb_startblock);

  pcb_asid.asid_changed = asid_changed;
  panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb_asid);

  PPP_REG_CB("osi", on_get_current_thread, on_get_current_thread);
  PPP_REG_CB("osi", on_get_process_pid, on_get_process_pid);
  PPP_REG_CB("osi", on_get_current_process_handle,
             on_get_current_process_handle);
  PPP_REG_CB("osi", on_get_process_handles, on_get_process_handles);
  PPP_REG_CB("osi", on_get_process_ppid, on_get_process_ppid);
  PPP_REG_CB("osi", on_get_current_process, on_get_current_process);
  PPP_REG_CB("osi", on_get_process, on_get_process);
  PPP_REG_CB("osi", on_get_processes, on_get_processes);
  PPP_REG_CB("osi", on_get_modules, on_get_modules);
  PPP_REG_CB("osi", on_get_mappings, on_get_mappings);
  PPP_REG_CB("osi", on_get_file_mappings, on_get_mappings);
  PPP_REG_CB("osi", on_get_mapping_by_addr, on_get_mapping_by_addr);
  PPP_REG_CB("osi", on_get_mapping_base_address_by_name,
             on_get_mapping_base_address_by_name);
  PPP_REG_CB("osi", on_has_mapping_prefix, on_has_mapping_prefix);

  // globals
  g_kernel_manager = std::unique_ptr<WindowsKernelManager>(
      new WindowsKernelManager(std::string(panda_os_name)));
  swapcontext_address = 0;
  g_initialized_kernel = false;

  return true;
#endif
  return false;
}

void uninit_plugin(void *_self) {
  printf("Unloading wintrospection plugin\n");
  // if we don't clear tb's when this exits we have TBs which can call
  // into our exited plugin.
  panda_do_flush_tb();
}
