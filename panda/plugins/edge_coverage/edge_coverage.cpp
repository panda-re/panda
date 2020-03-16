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

#ifdef CONFIG_SOFTMMU

#endif

using namespace std;

typedef target_ulong Asid;
typedef target_ulong Pc;

map <Asid, vector<Pc>> asid_trace; 

// Up to n-edge coverage 
int n;

// Called before each block, we have PC and ASID
void collect_edges(CPUState *env, TranslationBlock *tb) {

    target_ulong asid = panda_current_asid(env);
    target_ulong pc = panda_current_pc(env);

    // Gather the trace of pcs for this asid 
    asid_trace[asid].push_back(pc); 
}

bool init_plugin(void *self) {
    panda_arg_list *args; 
    args = panda_get_args("general");

    // Set the default value to 1-edge or basic block coverage  
    n = panda_parse_uint64_opt(args, "n", 1, "collect up-to-and-including n-edges");

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

    map<Asid, map<vector<Pc>, int>> final_map; 

    // From the traces in each asid, collect up to n-edges 
    for (auto kvp : asid_trace) { 
        map<vector<Pc>, int> edges;
        auto asid = kvp.first;
        auto pc_trace = kvp.second; 

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
        final_map[asid] = edges; 
    }

    // Write out each to a pandalog 
    for (auto kvp: final_map) { 
        auto asid = kvp.first;
        auto edge_map = kvp.second; 

        Panda__AsidEdges * ae = (Panda__AsidEdges *) malloc (sizeof (Panda__AsidEdges)); 
        *ae = PANDA__ASID_EDGES__INIT; 

        ae->n_edges = edge_map.size(); 
        Panda__Edge ** e = (Panda__Edge **) malloc (sizeof (Panda__Edge *) * edge_map.size()); 

        int i = 0;
        for (auto kvp : edge_map) { 
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
        ple.asid = asid; 
        ple.edge_coverage = ae; 
        pandalog_write_entry(&ple); 

        // Free everything I used
        for (int i = 0; i < edge_map.size(); i++) { 
            free(e[i]->pc);
            free(e[i]); 
        }
        free(e); 
        free(ae); 
    } 

}


