#ifndef __WINTROSPECTION_INT_FNS_H__
#define __WINTROSPECTION_INT_FNS_H__

// returns virtual address of EPROCESS data structure of currently running process
uint32_t get_current_proc(CPUState *env) ;

// returns pid, given virtual address of EPROCESS data structure
uint32_t get_pid(CPUState *env, uint32_t eproc) ;

// fills name (assumed alloced) for process given virtual address of EPROCESS data structure
void get_procname(CPUState *env, uint32_t eproc, char *name) ;

HandleObject *get_handle_object(CPUState *env, uint32_t eproc, uint32_t handle);

char *get_handle_object_name(CPUState *env, HandleObject *ho);

char *get_handle_name(CPUState *env, uint32_t eproc, uint32_t handle) ;

char * get_objname(CPUState *env, uint32_t obj) ;

uint32_t get_handle_table_entry(CPUState *env, uint32_t pHandleTable, uint32_t handle) ;

char *get_file_obj_name(CPUState *env, uint32_t fobj) ;



char *read_unicode_string(CPUState *env, uint32_t pUstr);

#endif
