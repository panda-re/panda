#ifndef __WINTROSPECTION_INT_FNS_H__
#define __WINTROSPECTION_INT_FNS_H__

char *make_pagedstr(void);

char *get_unicode_str(CPUState *cpu, PTR ustr);

// returns virtual address of EPROCESS data structure of currently running process
uint32_t get_current_proc(CPUState *cpu);

// returns next process in process list
PTR get_next_proc(CPUState *cpu, PTR eproc);

// returns true if eproc points to an EPROCESS structure
bool is_valid_process(CPUState *cpu, PTR eproc);

// returns pid,given virtual address of EPROCESS data structure
uint32_t get_pid(CPUState *cpu, uint32_t eproc) ;

// returns parent pid,given virtual address of EPROCESS data structure
PTR get_ppid(CPUState *cpu, uint32_t eproc);

PTR get_dtb(CPUState *cpu, PTR eproc);

// fills name (assumed alloced) for process given virtual address of EPROCESS data structure
void get_procname(CPUState *cpu, uint32_t eproc, char **name) ;

char *get_handle_object_name(CPUState *cpu, HandleObject *ho);

int64_t get_file_handle_pos(CPUState *cpu, uint32_t eproc, uint32_t handle) ;

char *get_handle_name(CPUState *cpu, uint32_t eproc, uint32_t handle) ;

char * get_objname(CPUState *cpu, uint32_t obj) ;

char *get_file_obj_name(CPUState *cpu, uint32_t fobj) ;

int64_t get_file_obj_pos(CPUState *cpu, uint32_t fobj) ;

char *read_unicode_string(CPUState *cpu, uint32_t pUstr);

const char *get_mod_basename(CPUState *cpu, PTR mod);

const char *get_mod_filename(CPUState *cpu, PTR mod);

PTR get_mod_base(CPUState *cpu, PTR mod);

PTR get_mod_size(CPUState *cpu, PTR mod);

PTR get_next_mod(CPUState *cpu, PTR mod);

void fill_osiproc(CPUState *cpu, OsiProc *p, PTR eproc);

void fill_osimod(CPUState *cpu, OsiModule *m, PTR mod, bool ignore_basename);

void add_mod(CPUState *cpu, OsiModules *ms, PTR mod, bool ignore_basename);

void on_get_current_process(CPUState *cpu, OsiProc **out_p);

void on_get_processes(CPUState *cpu, OsiProcs **out_ps);

// Getters for os-specific constants
uint32_t get_ntreadfile_esp_off(void);

uint32_t get_eproc_pid_off(void);

uint32_t get_eproc_name_off(void);

uint32_t get_kthread_kproc_off(void);

uint32_t get_eproc_objtable_off(void);

uint32_t get_obj_type_offset(void);

uint32_t handle_table_code(CPUState *cpu, uint32_t table_vaddr);

uint32_t handle_table_L1_addr(CPUState *cpu, uint32_t table_vaddr, uint32_t entry_num);

uint32_t handle_table_L2_addr(uint32_t L1_table, uint32_t L2);

uint32_t handle_table_L1_entry(CPUState *cpu, uint32_t table_vaddr, uint32_t entry_num);

uint32_t handle_table_L2_entry(uint32_t table_vaddr, uint32_t L1_table, uint32_t L2);

uint32_t handle_table_L3_entry(uint32_t table_vaddr, uint32_t L2_table, uint32_t L3);


#endif
