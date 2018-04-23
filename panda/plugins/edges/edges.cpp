
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

}

#include<map>
#include<set>


#ifdef CONFIG_SOFTMMU

#endif

using namespace std;

typedef target_ulong Asid;
typedef target_ulong Pc;
typedef pair<Pc, Pc> Edge; 

map<Asid, set<Edge>> asid_edges;
map<Asid, Pc> last_pc;

int collect_edges(CPUState *env, TranslationBlock *tb) {
    target_ulong asid = panda_current_asid(env);
    target_ulong pc = panda_current_pc(env);
    if (last_pc.count(asid) != 0) {               
        Edge e = make_pair(last_pc[asid], pc);
        asid_edges[asid].insert(e);
    }
    last_pc[asid] = pc;
    return 0;
}

bool init_plugin(void *self) {
    panda_cb pcb;
    pcb.before_block_exec = collect_edges;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    return true;
}


void uninit_plugin(void *) {
    for (auto kvp : asid_edges) {
        auto asid = kvp.first;
        auto edges = kvp.second;
        Panda__AsidEdges *pae = (Panda__AsidEdges *) malloc(sizeof(Panda__AsidEdges));
        *pae = PANDA__ASID_EDGES__INIT;
        pae->asid = asid;
        pae->edges = (Panda__Edge **) malloc(sizeof(Panda__Edge) * edges.size());
        uint32_t n = 0;
        for (auto e : edges) {
            pae->edges[n] = (Panda__Edge *) malloc(sizeof(Panda__Edge));
            *(pae->edges[n]) = PANDA__EDGE__INIT;
            pae->edges[n]->begin = e.first;
            pae->edges[n]->end = e.second;
            n++;
        }
        pae->n_edges = n;
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        ple.asid_edges = pae;
        pandalog_write_entry(&ple);
        for (uint32_t i=0; i<n; i++)
            free(pae->edges[i]);
        free(pae);
    }
}

