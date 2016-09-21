#ifndef __WINTROSPECTION_INT_FNS_H__
#define __WINTROSPECTION_INT_FNS_H__

// returns virtual address of EPROCESS data structure of currently running process
uint32_t get_current_proc(CPUState *cpu) ;

// returns pid, given virtual address of EPROCESS data structure
uint32_t get_pid(CPUState *cpu, uint32_t eproc) ;

// fills name (assumed alloced) for process given virtual address of EPROCESS data structure
void get_procname(CPUState *cpu, uint32_t eproc, char *name) ;

HandleObject *get_handle_object(CPUState *cpu, uint32_t eproc, uint32_t handle);

char *get_handle_object_name(CPUState *cpu, HandleObject *ho);

int64_t get_file_handle_pos(CPUState *cpu, uint32_t eproc, uint32_t handle) ;

char *get_handle_name(CPUState *cpu, uint32_t eproc, uint32_t handle) ;

char * get_objname(CPUState *cpu, uint32_t obj) ;

uint32_t get_handle_table_entry(CPUState *cpu, uint32_t pHandleTable, uint32_t handle) ;

char *get_file_obj_name(CPUState *cpu, uint32_t fobj) ;

int64_t get_file_obj_pos(CPUState *cpu, uint32_t fobj) ;

char *read_unicode_string(CPUState *cpu, uint32_t pUstr);

#endif
