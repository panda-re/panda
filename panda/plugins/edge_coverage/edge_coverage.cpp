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


#ifdef CONFIG_SOFTMMU

#endif

using namespace std;

typedef target_ulong Asid;
typedef target_ulong Pc;
typedef pair<Pc, Pc> Edge; 
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

map<Asid, ProcessData> process_datas;

target_ulong MY_TARGET_ASID = 0; // Set to 0 to collect everything

// Called before each block, we have PC and ASID
void collect_edges(CPUState *env, TranslationBlock *tb) {

    OsiProc *current = get_current_process(env); 
    target_ulong asid = panda_current_asid(env);
    target_ulong pc = panda_current_pc(env);

    // Only trace our asid (0 is all asids) 
    if (MY_TARGET_ASID != 0 && asid != MY_TARGET_ASID) return; 

    if (process_datas.find(asid) == process_datas.end() && current) {
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
    }

    // Actually store the PC, in both blocks and edges for now
    if (last_pc.count(asid) != 0) { 
        // If we currently have a pc stored for this ASID, 
        // let's add an edge from the last one we saw in this ASID (process) to this new one 
        unsigned int block_size = tb->size;
        Block b = make_pair(pc, block_size);
        Edge e = make_pair(last_pc[asid], pc); 
        asid_edges[asid].insert(e);
        blocks[asid].insert(b);
    }
    last_pc[asid] = pc;
}

bool init_plugin(void *self) {
    panda_require("osi");
    assert(init_osi_api()); // Setup OSI inspection
    panda_cb pcb;
    pcb.before_block_exec = collect_edges;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    printf("Initialized coverage plugin\n");
    return true;
}


void uninit_plugin(void *) {
    int i = 0;
    for (auto kvp : asid_edges) {
        auto p = process_datas.find(kvp.first); 
        printf("Process: %s, ID = %d, count = %lu ASID=" TARGET_FMT_lx "\n", p->second.name, ++i, kvp.second.size(), kvp.first);
    }
    printf("Unload coverage plugin\n");

    if (pandalog) {
        int map_size = asid_edges.size();
        printf("asid_edges size: %d\n", map_size);
        for (auto kvp : asid_edges) { 
            auto asid = kvp.first; // asid 
            auto edges = kvp.second; // set of edges
            Panda__AsidEdges * ae = (Panda__AsidEdges *) malloc (sizeof (Panda__AsidEdges));
            *ae = PANDA__ASID_EDGES__INIT;
            ae->n = 2; // for now just do 2-edge coverage 
            ae->asid = asid; 
            int num_edges = edges.size(); 
            Panda__Edge** e = (Panda__Edge **) malloc (sizeof (Panda__Edge *) * num_edges);
            printf("edges size: %d\n", num_edges);
            int j = 0;
            for (auto edge : edges) { 
                (e[j]) = (Panda__Edge *) malloc (sizeof (Panda__Edge)); 
                *(e[j]) = PANDA__EDGE__INIT; 
                e[j]->begin = edge.first;
                e[j]->end = edge.second;
                j++;
                 
            }
            ae->n_edges = edges.size(); 
            ae->edges = e; 
            Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
            ple.edge_coverage = ae; 
            pandalog_write_entry(&ple); 

            // Free everything after we are done  
            for (int i = 0; i < num_edges; i++) free(e[i]); 
            free(ae->edges);
            free(ae); 
        }
    }
}
