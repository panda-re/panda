#ifndef __TAINT_EXT_H__
#define __TAINT_EXT_H__

#include <dlfcn.h>
#include "panda_plugin.h"

typedef void(*taint_enable_taint_t)(void);
static taint_enable_taint_t __taint_enable_taint = NULL;
inline void taint_enable_taint(void ){
    assert(__taint_enable_taint);
    return __taint_enable_taint();
}
typedef int(*taint_enabled_t)(void);
static taint_enabled_t __taint_enabled = NULL;
inline int taint_enabled(void ){
    assert(__taint_enabled);
    return __taint_enabled();
}
typedef void(*taint_label_ram_t)(uint64_t,uint32_t);
static taint_label_ram_t __taint_label_ram = NULL;
inline void taint_label_ram(uint64_t pa,uint32_t l){
    assert(__taint_label_ram);
    return __taint_label_ram(pa,l);
}
typedef uint32_t(*taint_query_ram_t)(uint64_t);
static taint_query_ram_t __taint_query_ram = NULL;
inline uint32_t taint_query_ram(uint64_t pa){
    assert(__taint_query_ram);
    return __taint_query_ram(pa);
}
typedef uint32_t(*taint_query_reg_t)(int,int);
static taint_query_reg_t __taint_query_reg = NULL;
inline uint32_t taint_query_reg(int reg_num,int offset){
    assert(__taint_query_reg);
    return __taint_query_reg(reg_num,offset);
}
typedef void(*taint_delete_ram_t)(uint64_t);
static taint_delete_ram_t __taint_delete_ram = NULL;
inline void taint_delete_ram(uint64_t pa){
    assert(__taint_delete_ram);
    return __taint_delete_ram(pa);
}
typedef uint32_t(*taint_occ_ram_t)(void);
static taint_occ_ram_t __taint_occ_ram = NULL;
inline uint32_t taint_occ_ram(void ){
    assert(__taint_occ_ram);
    return __taint_occ_ram();
}
typedef uint32_t(*taint_max_obs_ls_type_t)(void);
static taint_max_obs_ls_type_t __taint_max_obs_ls_type = NULL;
inline uint32_t taint_max_obs_ls_type(void ){
    assert(__taint_max_obs_ls_type);
    return __taint_max_obs_ls_type();
}
typedef void(*taint_clear_tainted_computation_happened_t)(void);
static taint_clear_tainted_computation_happened_t __taint_clear_tainted_computation_happened = NULL;
inline void taint_clear_tainted_computation_happened(void ){
    assert(__taint_clear_tainted_computation_happened);
    return __taint_clear_tainted_computation_happened();
}
typedef int(*taint_tainted_computation_happened_t)(void);
static taint_tainted_computation_happened_t __taint_tainted_computation_happened = NULL;
inline int taint_tainted_computation_happened(void ){
    assert(__taint_tainted_computation_happened);
    return __taint_tainted_computation_happened();
}
typedef void(*taint_clear_taint_state_changed_t)(void);
static taint_clear_taint_state_changed_t __taint_clear_taint_state_changed = NULL;
inline void taint_clear_taint_state_changed(void ){
    assert(__taint_clear_taint_state_changed);
    return __taint_clear_taint_state_changed();
}
typedef int(*taint_taint_state_changed_t)(void);
static taint_taint_state_changed_t __taint_taint_state_changed = NULL;
inline int taint_taint_state_changed(void ){
    assert(__taint_taint_state_changed);
    return __taint_taint_state_changed();
}
typedef void(*taint_clear_taint_state_read_t)(void);
static taint_clear_taint_state_read_t __taint_clear_taint_state_read = NULL;
inline void taint_clear_taint_state_read(void ){
    assert(__taint_clear_taint_state_read);
    return __taint_clear_taint_state_read();
}
typedef int(*taint_taint_state_read_t)(void);
static taint_taint_state_read_t __taint_taint_state_read = NULL;
inline int taint_taint_state_read(void ){
    assert(__taint_taint_state_read);
    return __taint_taint_state_read();
}
#define API_PLUGIN_NAME "taint"
#define IMPORT_PPP(module, func_name) { \
 __##func_name = (func_name##_t) dlsym(module, #func_name); \
 char *err = dlerror(); \
 if (err) { \
    printf("Couldn't find func_name function in library %s.\n", API_PLUGIN_NAME); \
    printf("Error: %s\n", err); \
    return false; \
 } \
}
inline bool init_taint_api(void){
    void *module = panda_get_plugin_by_name("panda_" API_PLUGIN_NAME ".so");
    if (!module) {
        printf("In trying to add plugin, couldn't load %s plugin\n", API_PLUGIN_NAME);
        return false;
    }
    dlerror();
IMPORT_PPP(module, taint_enable_taint)
IMPORT_PPP(module, taint_enabled)
IMPORT_PPP(module, taint_label_ram)
IMPORT_PPP(module, taint_query_ram)
IMPORT_PPP(module, taint_query_reg)
IMPORT_PPP(module, taint_delete_ram)
IMPORT_PPP(module, taint_occ_ram)
IMPORT_PPP(module, taint_max_obs_ls_type)
IMPORT_PPP(module, taint_clear_tainted_computation_happened)
IMPORT_PPP(module, taint_tainted_computation_happened)
IMPORT_PPP(module, taint_clear_taint_state_changed)
IMPORT_PPP(module, taint_taint_state_changed)
IMPORT_PPP(module, taint_clear_taint_state_read)
IMPORT_PPP(module, taint_taint_state_read)
return true;
}

#undef API_PLUGIN_NAME
#undef IMPORT_PPP

#endif
