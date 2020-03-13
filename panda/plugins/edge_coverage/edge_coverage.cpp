// Generate a drcov trace file from a panda recording
// TODO: the output isn't quite right, Lighthouse shows no coverage

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <cstdio>

#include "panda/plugin.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
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

/*typedef pair<Pc, Pc> Edge; 
typedef pair<Pc, unsigned int> Block; 

map<Asid, set<Block>> blocks;
map<Asid, set<Edge>> asid_edges;
map<Asid, Pc> last_pc;

struct ProcessData {
    const char* name;
    target_ulong pid;
    target_ulong load_address;
    target_ulong size;
}; 
*/
map <Asid, vector<Pc>> asid_trace; 

//map<Asid, ProcessData> process_datas;

target_ulong MY_TARGET_ASID = 0; // Set to 0 to collect everything
int n;

// Called before each block, we have PC and ASID
void collect_edges(CPUState *env, TranslationBlock *tb) {

    //OsiProc *current = get_current_process(env); 
    target_ulong asid = panda_current_asid(env);
    target_ulong pc = panda_current_pc(env);

    // Only trace our asid (0 is all asids) 
    if (MY_TARGET_ASID != 0 && asid != MY_TARGET_ASID) return; 

    /*if (process_datas.find(asid) == process_datas.end() && current) {
        target_ulong load_addr = 0;
        target_ulong size = 0;

        GArray * libraries = get_libraries(env, current); 
        if (libraries && libraries->len > 0) {

            // Add this process to the asid -> process data map 
            OsiModule *self = &g_array_index(libraries, OsiModule, 0); 
            load_addr = self->base;
            size = self->size;
            if (self->file != NULL) {
                printf("LOADED %s asid=0x" TARGET_FMT_lx " at PC 0x" TARGET_FMT_lx ": low = " TARGET_FMT_lx 
                        ", relative= 0x" TARGET_FMT_lx "\n", self->file, asid, pc, load_addr, pc-load_addr);
                ProcessData p;
                p.name = current->name;
                p.pid = current->pid;
                p.load_address = load_addr;
                p.size = size;
                process_datas.insert(make_pair(asid, p));
            }
        }
    }*/

    asid_trace[asid].push_back(pc); 
    // Actually store the PC, in both blocks and edges for now
    /*if (last_pc.count(asid) != 0) { 
        // If we currently have a pc stored for this ASID, 
        // let's add an edge from the last one we saw in this ASID (process) to this new one 
        unsigned int block_size = tb->size;
        Block b = make_pair(pc, block_size);
        Edge e = make_pair(last_pc[asid], pc); 
        asid_edges[asid].insert(e);
        blocks[asid].insert(b);
    }
    last_pc[asid] = pc; */
}

bool init_plugin(void *self) {
    panda_arg_list *args; 
    args = panda_get_args("general"); 
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
    map<Asid, map<vector<Pc>, int>> final_map; 
    for (auto kvp : asid_trace) { 
        map<vector<Pc>, int> edges;
        auto asid = kvp.first;
        auto pc_trace = kvp.second; 

        for (int k = 1; k <= n; k++) {
            for (int i = 0; i < pc_trace.size(); i++) {
                vector<Pc> edge;
                for (int j = 0; j < k; j++) { 
                    edge.push_back(pc_trace[i + j]); 
                }
                if (edges.find(edge) != edges.end())  edges[edge] += 1;
                else  edges[edge] = 1; 
            }
        }        
        final_map[asid] = edges; 
    }

    for (auto kvp: final_map) { 
        auto asid = kvp.first;
        auto edge_map = kvp.second; 

        Panda__AsidEdges * ae = (Panda__AsidEdges *) malloc (sizeof (Panda__AsidEdges)); 
        *ae = PANDA__ASID_EDGES__INIT; 
        ae->asid = asid; 

        ae->n_edges = edge_map.size(); 
        Panda__Edge ** e = (Panda__Edge **) malloc (sizeof (Panda__Edge *) * edge_map.size()); 

        int i = 0;
        for (auto kvp : edge_map) { 
            auto n_edge = kvp.first;
            auto hit_count = kvp.second;

            e[i] = (Panda__Edge *) malloc (sizeof (Panda__Edge)); 
            *(e[i]) = PANDA__EDGE__INIT;

            e[i]->n = n_edge.size(); 
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
        ple.edge_coverage = ae; 
        pandalog_write_entry(&ple); 
    }
}


