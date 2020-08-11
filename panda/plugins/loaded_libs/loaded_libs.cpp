#define __STDC_FORMAT_MACROS

#include <cstdio>

#include "panda/plugin.h"

extern "C" {

    bool init_plugin(void *);
    void uninit_plugin(void *);

#include "osi/osi_types.h"
#include "osi/osi_ext.h"
} 

#include "asidstory/asidstory.h"

#include<map>
#include<vector> 
#include<set>
#include<iostream>
using namespace std; 

typedef target_ulong Asid;
map<Asid, vector<vector<OsiModule>>> asid_module_list; 

//bool asid_changed(CPUState *cpu, target_ulong old_pgd, target_ulong new_pgd);

const char* program_name; 



void get_libs(CPUState *env) {
    OsiProc *current =  get_current_process(env); 
    target_ulong asid = panda_current_asid(env); 

    if (current != NULL) {
        GArray *ms = get_mappings(env, current); 

        //if (current) printf("current->name: %s  asid: " TARGET_FMT_lx "\n", current->name, asid);
        if (program_name != NULL && strcmp(current->name, program_name) != 0) return; 
        if (ms == NULL) return; 

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
    }

}


void asidstory_proc_changed(CPUState *env, target_ulong asid, OsiProc *proc) {
    get_libs(env);
}

bool asid_changed(CPUState *env, target_ulong old_asid, target_ulong new_asid) {
    get_libs(env);
    return false; // allow OS to change ASID
}

void before_block(CPUState *env, TranslationBlock *tb) {
    // check up on module list ever 50 bb
    if (((float)(random())) / RAND_MAX < 0.02) 
        get_libs(env);
}


bool init_plugin(void *self) {
    panda_require("osi"); 
    assert(init_osi_api());
    panda_require("asidstory");

    panda_cb pcb;
    pcb.asid_changed = asid_changed;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);

    // we'll let asidstory tell us when the process changes
    // which should catch execv as well 
    PPP_REG_CB("asidstory", on_proc_change, asidstory_proc_changed);
    
    pcb.before_block_exec = before_block;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    
    panda_arg_list *args; 
    args = panda_get_args("loaded_libs"); 
    program_name = panda_parse_string_opt(args, "program_name", NULL, "program name to collect libraries for"); 
    return true;
}

void uninit_plugin(void *self) { 
    //size_t nm = asid_module_list.size(); 
    if (!pandalog) return; 

    cout << "asid_module_list is " << asid_module_list.size() << " items\n";

    for (auto kvp : asid_module_list) { 
        auto asid = kvp.first;
        auto all_module_list = kvp.second; // vector<vector<OsiModule>>
        cout << "asid=" << hex << asid << " has " << dec << all_module_list.size() << "modules\n";
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
