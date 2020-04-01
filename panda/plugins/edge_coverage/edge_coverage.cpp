#define __STDC_FORMAT_MACROS

#include <cstdio>

#include "panda/plugin.h"

extern "C" {

    bool init_plugin(void *);
    void uninit_plugin(void *);

#include <stdint.h>

#include "panda/plog.h"
#include "osi/osi_types.h"
#include "osi/osi_ext.h"

}

#include<fstream>
#include<map>
#include<set>
#include <iomanip>
#include <vector>
#include <iostream> 
#include<string> 

#ifdef CONFIG_SOFTMMU

#endif

using namespace std;

typedef target_ulong Asid;
typedef target_ulong Pc;

map <Asid, vector<Pc>> asid_trace; 

// Up to n-edge coverage 
int n;
Pc first_instr;
Pc last_instr;
string program_name;
Asid target_asid;
bool no_kernel;

vector<Pc> pc_trace;
// Called before each block, we have PC and ASID
void collect_edges(CPUState *env, TranslationBlock *tb) {

    target_ulong asid = panda_current_asid(env);
    target_ulong pc = panda_current_pc(env);
    uint64_t instr = rr_get_guest_instr_count(); 

    if (no_kernel && panda_in_kernel(env)) return;
    //printf("asid: " TARGET_FMT_lx "pc: " TARGET_FMT_lx, asid, pc);  
    if (target_asid == asid && instr >= first_instr && instr <= last_instr) {
        //printf("asid: " TARGET_FMT_lx "pc: " TARGET_FMT_lx "\n", asid, pc);  
        pc_trace.push_back(pc); 
    }
    // Gather the trace of pcs for this asid 
    asid_trace[asid].push_back(pc); 
}

bool init_plugin(void *self) {
    panda_arg_list *args; 
    args = panda_get_args("edge_coverage");

    // Set the default value to 1-edge or basic block coverage  
    n = panda_parse_uint64_opt(args, "n", 1, "collect up-to-and-including n-edges");
    first_instr = panda_parse_ulong_opt(args, "first_instr", 0, "first instruction");
    last_instr = panda_parse_ulong_opt(args, "last_instr", 0, "last instruction"); 
    target_asid = panda_parse_ulong_opt(args, "asid", 0, "asid");  
    no_kernel = panda_parse_bool_opt(args, "no_kernel", "disable kernel pcs"); 

    printf("n: %d, first_instr: " TARGET_FMT_lx " last_instr: " TARGET_FMT_lx " asid: "
            TARGET_FMT_lx, n, first_instr, last_instr, target_asid); 
    cout << " Program name: " << program_name << endl;;  
    
    panda_require("osi");
    assert(init_osi_api()); // Setup OSI inspection
    panda_cb pcb;
    pcb.before_block_exec = collect_edges;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    printf("Initialized coverage plugin\n");
    return true;
}


void uninit_plugin(void *) {

    if (!pandalog) return; 

    map<vector<Pc>, int> edges;

    for (int k = 1; k <= n; k++) { 
        for (int i = 0; i < pc_trace.size(); i++) {
            // Build the edge (vector) 
            vector<Pc> edge;
            for (int j = 0; j < k; j++) { 
                edge.push_back(pc_trace[i + j]); 
            }
            // Add the edge to the map for this asid and update its count  
            if (edges.find(edge) != edges.end())  edges[edge] += 1;
            else  edges[edge] = 1; 
        }
    }

    Panda__AsidEdges * ae = (Panda__AsidEdges *) malloc (sizeof (Panda__AsidEdges)); 
    *ae = PANDA__ASID_EDGES__INIT; 

    ae->n_edges = edges.size(); 
    Panda__Edge ** e = (Panda__Edge **) malloc (sizeof (Panda__Edge *) * edges.size()); 

    int i = 0;
    for (auto kvp : edges) { 
        auto n_edge = kvp.first;
        auto hit_count = kvp.second;

        e[i] = (Panda__Edge *) malloc (sizeof (Panda__Edge)); 
        *(e[i]) = PANDA__EDGE__INIT;

        //e[i]->n = n_edge.size(); 
        uint64_t *pc_list = (uint64_t *) malloc (sizeof (uint64_t) * (n_edge.size()));
        int j = 0;
        for (auto edge : n_edge) {
            pc_list[j++] = edge; 
        }
        e[i]->pc = pc_list;
        e[i]->n_pc = n_edge.size();
        e[i]->hit_count = hit_count; 
        i++; 
    } 
    ae->edges = e; 


    Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT; 
    ple.has_asid = 1;
    ple.asid = target_asid; 
    ple.edge_coverage = ae; 
    pandalog_write_entry(&ple); 

    // Free everything I used
    for (int i = 0; i < edges.size(); i++) { 
        free(e[i]->pc);
        free(e[i]); 
    }
    free(e); 
    free(ae); 
} 

//}


