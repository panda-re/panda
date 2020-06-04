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
#include "track_intexc/track_intexc_ext.h"

}

#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <iomanip>
#include <vector>

#ifdef CONFIG_SOFTMMU

#endif

using namespace std;

typedef target_ulong Asid;
typedef target_ulong Pc;

target_ulong start_main = 0;

map <Asid, vector<Pc>> asid_trace; 

bool debug=false;

// Up to n-edge coverage 
int n;


map<target_ulong,target_ulong> last_bb_start;
map<target_ulong,bool> last_bb_was_split;
map<target_ulong,bool> last_bb_was_exception;
map<target_ulong,bool> last_bb_intexc;
map<target_ulong,target_ulong> last_bb_before_intexc;

bool saw_main = false;


void after_block(CPUState *env, TranslationBlock *tb, uint8_t exitCode) {

    // only paying attention to one program and haven't seen main yet..
    if (start_main && !saw_main) 
        return;

    target_ulong asid = panda_current_asid(env);
    
    // dont record pc if we are in exception or interrupt code
    if (check_in_exception() || check_in_interrupt()) 
        return;
    
    // dont record pc if last block was split
    if (last_bb_was_split.count(asid) != 0 && !last_bb_was_split[asid])
        last_bb_start[asid] = tb->pc;
    
    // keep track of if last bb was split
    last_bb_was_split[asid] = tb->was_split; 
    
}


void before_block(CPUState *env, TranslationBlock *tb) {
    
    if (start_main) {
        // we are only paying attention to edges within some program
        // and are waiting to see main
        if (tb->pc == start_main) {
            //   printf("saw main");
            saw_main = true;
        }
        if (!saw_main)
            return;
    }
    
    target_ulong asid = panda_current_asid(env);
    bool intexc = (check_in_exception() || check_in_interrupt());
    
    // we can only know transition if we know where we were for this asid last
    if (last_bb_intexc.count(asid) != 0) {
        
        // four possibilities
        
        // 1. transition from reg to intexc code
        if (!last_bb_intexc[asid] && intexc) {
            // remember start pc of last bb before intexc
            if (debug) 
                cout << "trans from reg to intexc -- saving last_bb_before_intexc[" 
                     << hex << asid << "]=" << last_bb_start[asid] << "\n";
            last_bb_before_intexc[asid] = last_bb_start[asid];
            goto done;
        }
        
        // 2. transition from int/exc code to reg
        if (last_bb_intexc[asid] && !intexc) {
            // if this bb is just same as the last one before
            // the int/exc, we ignore
            if (debug) 
                cout << "trans from intexc to reg\n";
            if (tb->pc == last_bb_before_intexc[asid]) {
                cout << "same last bb\n";
                last_bb_start[asid] = tb->pc;
                goto done;
            }
            // bbs have different start pc. 
            // add bb so we'll get an edge that elides away all
            // the intexc code
            if (debug) {
                cout << "not same last bb\n";
                cout << "adding to trace last_bb_before_intexc["
                     << hex << asid << "]=" << last_bb_before_intexc[asid] << "\n";
                cout << "and setting last_bb_start[" << hex << asid << "]=" << tb->pc << "\n";
            }

            asid_trace[asid].push_back(last_bb_before_intexc[asid]);                     
            // update pc in case we get longjmped
            last_bb_start[asid] = tb->pc;
        }
        
        // 3. no transition && we are in regular code
        if (!last_bb_intexc[asid] && !intexc) {
            // ugh last bb was split so we dont update trace yet
            if (debug) 
                cout << "no trans and in reg code\n";
            if (last_bb_was_split[asid]) {
                if (debug) 
                    cout << "but last bb was split\n";
                goto done;
            }
            if (debug) {
                cout << "last bb not split\n";
                cout << "adding to trace last_bb_start["
                     << hex << asid << "]=" << last_bb_start[asid] << "\n";        
                cout << "and setting last_bb_start[" << asid << "]=" << tb->pc << "\n";
            }
            
            // update trace in normal way
            asid_trace[asid].push_back(last_bb_start[asid]);                 
            // update pc in case we get longjmped
            last_bb_start[asid] = tb->pc; 
        }
    }
    

    // 4. last bb was intexc and so is this one
    // -- nothing to do

    // keep track of last intexc value to be able
    // to observe transition
done:
    last_bb_intexc[asid] = intexc;
}


bool pandalog_trace = false;

bool init_plugin(void *self) {

    panda_require("track_intexc");
    assert(init_track_intexc_api());

    panda_arg_list *args; 
    args = panda_get_args("edge_coverage");

    // Set the default value to 1-edge or basic block coverage  
    n = panda_parse_uint64_opt(args, "n", 1, "collect up-to-and-including n-edges");
    //    no_kernel = panda_parse_bool_opt(args, "no_kernel", "disable kernel pcs"); 
    pandalog_trace = panda_parse_bool_opt(args, "trace", "output trace to pandalog");
    const char *start_main_str = panda_parse_string_opt(args, "main", nullptr,
                                            "hex addr of main");
    if (start_main_str != nullptr) {
        start_main = strtoul(start_main_str, NULL, 16);
        printf ("edge coverage for just one program: start_main = 0x" TARGET_FMT_lx "\n", start_main);
    }
    else 
        printf ("edge coverage for all asids and all code\n");
    
    panda_require("osi");
    assert(init_osi_api()); // Setup OSI inspection
    panda_cb pcb;
    pcb.before_block_exec = before_block;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    pcb.after_block_exec = after_block;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
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
        ofstream tracef;
        for (int k = 1; k <= n; k++) { 
            for (int i = 0; i < pc_trace.size(); i++) {
                // Build the edge (vector) 
                vector<Pc> edge;
                for (int j = 0; j < k; j++) { 
                    if (i+j < pc_trace.size()) 
                        edge.push_back(pc_trace[i + j]);                     
                }
                // Add the edge to the map for this asid and update its count  
                if (edges.find(edge) != edges.end())  edges[edge] += 1;
                else  edges[edge] = 1; 
            }
        }
        if (pandalog_trace) {
            Panda__AsidTrace *at = (Panda__AsidTrace *) malloc (sizeof(Panda__AsidTrace));
            *at = PANDA__ASID_TRACE__INIT;
            at->pcs = (uint64_t *) malloc(sizeof(uint64_t) * pc_trace.size());
            int i=0;
            for (auto pc : pc_trace) 
                at->pcs[i++] = pc;
            at->n_pcs = pc_trace.size();	  
            Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
            ple.has_asid = 1;
            ple.asid = asid;
            ple.trace = at;
            pandalog_write_entry(&ple);
            free(at->pcs);
            free(at);
            final_map[asid] = edges; 
        }
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


