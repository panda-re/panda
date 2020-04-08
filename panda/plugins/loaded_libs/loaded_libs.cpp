#define __STDC_FORMAT_MACROS

#include <cstdio>

#include "panda/plugin.h"

extern "C" {

    bool init_plugin(void *);
    void uninit_plugin(void *);

#include "osi/osi_types.h"
#include "osi/osi_ext.h"
} 

#include<map>
#include <vector> 
#include<set>
using namespace std; 

typedef target_ulong Asid;
map<Asid, vector<vector<OsiModule>>> asid_module_list; 

bool asid_changed(CPUState *cpu, target_ulong old_pgd, target_ulong new_pgd);

const char* program_name; 

bool asid_changed(CPUState *env, target_ulong old_pgd, target_ulong new_pgd) {
    OsiProc *current =  get_current_process(env); 
    target_ulong asid = panda_current_asid(env); 
    GArray *ms = get_libraries(env, current); 

    //if (current) printf("current->name: %s  asid: " TARGET_FMT_lx "\n", current->name, asid);
    if (program_name != NULL && strcmp(current->name, program_name) != 0) return false; 
    if (ms == NULL) return false; 

    vector<OsiModule> module_list;
    for (int i = 0; i < ms->len; i++) { 
        OsiModule *m = &g_array_index(ms, OsiModule, i); 
        OsiModule mm; 
        mm.modd = m->modd;
        mm.base = m->base;
        mm.size = m->size; 
        if (m->file) mm.file = strdup(m->file); 
        else mm.file = strdup("Unknown_file"); 
        if (m->name) mm.name = strdup(m->name); 
        else mm.name = strdup("Unknown_name");
        module_list.push_back(mm); 
    }
    asid_module_list[asid].push_back(module_list); 

    return false;
}

bool init_plugin(void *self) {
    panda_require("osi"); 
    assert(init_osi_api());

    panda_cb pcb;
    pcb.asid_changed = asid_changed;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);

    panda_arg_list *args; 
    args = panda_get_args("general"); 
    program_name = panda_parse_string_opt(args, "program_name", NULL, "program name to collect libraries for"); 
    return true;
}

void uninit_plugin(void *self) { 
    //size_t nm = asid_module_list.size(); 
    if (!pandalog) return; 

    for (auto kvp : asid_module_list) { 
        auto asid = kvp.first;
        auto all_module_list = kvp.second; // vector<vector<OsiModule>>
        int max_size = 0; 
        int i, idx;
        i = idx = 0; 
        // We're going to choose the one with the most amount of loaded modules 
        for (auto module_list : all_module_list) { 
            if (module_list.size() > max_size) { 
                max_size = module_list.size();
                idx = i; 
            }
            i++;
        }

        Panda__LoadedLibs * ll = (Panda__LoadedLibs *) malloc (sizeof (Panda__LoadedLibs)); 
        *ll = PANDA__LOADED_LIBS__INIT; 

        Panda__Module** m = (Panda__Module **) malloc (sizeof (Panda__Module *) * max_size);  
        i = 0; 
        for (auto module : all_module_list[idx]) {
            m[i] = (Panda__Module *) malloc (sizeof (Panda__Module)); 
            *(m[i]) = PANDA__MODULE__INIT; 
            m[i]->name = module.name; 
            m[i]->file = module.file;
            m[i]->base_addr = module.base; 
            m[i]->size = module.size; 
            i++;
        }
        ll->modules = m;  
        ll->n_modules = max_size;   
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT; 
        ple.has_asid = 1;
        ple.asid = asid;
        ple.asid_libraries =  ll; 
        pandalog_write_entry(&ple); 

        // Free things!
        for (int i = 0; i < max_size; i++) 
            free(m[i]); 
        free(m);
        free(ll); 

    }
}
