/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
 PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

extern "C" {   
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
}

#include "panda/plugin.h"
#include "taint2/taint2.h"

extern "C" {   
//#include "osi/osi_types.h"
//#include "osi/osi_ext.h"
#include "taint2/taint2_ext.h"
//#include "asidstory/asidstory_ext.h"
#include "panda/plog.h"
}

#include <sstream>
#include <iostream>
#include <fstream>
#include <map>
#include <set>

using namespace std;

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
}

#ifdef CONFIG_SOFTMMU

extern ram_addr_t ram_size;


char *replay_name; 



bool taint_on = false;

void ipflow_enable_taint(CPUState *env) {
    if (rr_in_replay())
        replay_name = strdup(rr_nondet_log->short_name);
    else
        replay_name = strdup("Live Run");
    printf ("ipflow plugin is enabling taint\n");
    taint2_enable_taint();
    taint_on = true;
}

typedef uint32_t Tlabel;
typedef uint64_t Asid;
typedef string ProcName;
typedef uint64_t Pid;

struct NamePid {
    ProcName name;
    Pid pid;
    Asid asid;
    
    bool operator<(const NamePid &rhs) const {
        if (name < rhs.name) return true;
        if (name > rhs.name) return false;
        if (pid < rhs.pid) return true;
        if (pid > rhs.pid) return false;
        return (asid < rhs.asid);
    }
    
    string str() {
        stringstream ss;
        ss << "[" << name << "," << pid << "," << asid << "]";
        return ss.str();       
    }

};


map<string, Tlabel> proclib2label;
map<Tlabel, string> label2proclib;

NamePid curr_proc;
string libname;
Tlabel curr_label;

map<string, uint32_t> name2count;
map<NamePid, string> proc2shortname;

map<NamePid, OsiModules> proc2libs;

set<NamePid> procs;


bool have_label = false;

// called before every bb runs.
int getprocessandlibs(CPUState *cpu, TranslationBlock *tb) {

    OsiProc *proc = asidstory_current_proc();
    if (proc && !panda_in_kernel(first_cpu)) {
        // we know the current process.
        curr_proc = {proc->name, proc->pid, proc->asid};                    
        if (procs.count(curr_proc) == 0) {
            // this is a new name-pid.  If this is the first instance
            // this process name in our replay, we'll use short version
            procs.insert(curr_proc);
            if (name2count.count(curr_proc.name) == 0)
                proc2shortname[curr_proc] =  curr_proc.name;
            else
                proc2shortname[curr_proc] =  curr_proc.name + to_string(1+name2count[curr_proc.name]);
            name2count[curr_proc.name] += 1;           
        }
        // also get the current set of libraries
        OsiModules *libs = get_libraries(first_cpu, proc);
        target_ulong pc = panda_current_pc(first_cpu);
        bool found_lib = false;
        if (libs) { 
            for (int i=0; i < libs->num; i++) {
                OsiModule lib = libs->module[i];
                if (lib.base <= pc && pc <= lib.base + lib.size) {
                    libname = lib.name;
                    found_lib = true;
                    break;
                }
            }                        
        }
        free_osimodules(libs);        
        // if we know process and libs, we can have a label
        if (found_lib) {
            have_label = true;
            auto pl = proc2shortname[curr_proc] + "--" + libname;
            if (proclib2label.count(pl) == 0) {
                // its a new label
                curr_label = 1 + proclib2label.size();
                proclib2label[pl] = curr_label;
                label2proclib[curr_label] = pl;
                cout << "New label -- " << curr_label << " " << proc2shortname[curr_proc] 
                     << " [" << curr_proc.name << "] " << curr_proc.pid 
                     << " " << libname << "\n";
            }
            else 
                curr_label = proclib2label[pl];
        }

    }    

    return 0;
}

/*
  Called *after* a store to virtual addr happens
  Paint taint label on value stored in memory.
  Label corresponds to current process, if known.
*/

// paddr is where value was stored
// size is number of bytes stored
void ipflow_store(Addr reg, uint64_t paddr, uint64_t size) {
    if (!taint_on) return;

    // paddr of mem-mapped IO is sometimes very large
    if (paddr == -1 || paddr >= ram_size) return;

    if (have_label) {
        for (int i=0; i<size; i++) {
            taint2_label_ram(paddr+i, curr_label);
        }

    }
}


struct IpFlow {
    Tlabel from_label;
    Tlabel to_label;

    IpFlow(Tlabel fl, Tlabel tl) : from_label(fl), to_label(tl) {}

    bool operator<(const IpFlow &other) const {
        if (from_label < other.from_label) return true;
        if (from_label > other.from_label) return false;
        return (to_label < other.to_label);
    }

    bool operator==(const IpFlow &other) const {
        return 
            (from_label == other.from_label 
             && to_label == other.to_label);
    }
};


struct IpfStats {
    uint64_t count;
    uint64_t first_instr;
    uint64_t last_instr;        
};


// an inter-process flow is label -> label
// since a label is a process
map<IpFlow, IpfStats> ipflow;


// label tells us which process is reading this data
// other_label tells us which process wrote this data
// So if other_label != label, we have an inter-process
// info-flow
int collect_flow(Tlabel st_label, void *stuff) {

    Tlabel ld_label = curr_label;

    if (ld_label != st_label) {

        IpFlow ipf(st_label, ld_label);

        if (ipflow.count(ipf) == 0) {
            uint64_t instr = rr_get_guest_instr_count();
            IpfStats s = {1, instr, instr};
            ipflow[ipf] = s;
        }
        else {
            ipflow[ipf].count ++;
            ipflow[ipf].last_instr = rr_get_guest_instr_count();            
        }

    }
    return 0;
}



// NOTE: called *after* a load from a virt addr 
void taint_mmio_load(Addr reg, uint64_t paddr, uint64_t size) {
    if (!taint_on) return;

    if (paddr == -1 || paddr >= ram_size) return;

    uint32_t num_tainted = 0;
    for (int i=0; i<size; i++) 
        num_tainted += taint2_query_ram(paddr+i);        
        
        if (num_tainted) {
            // some of the data we are loading is tainted.
            // collect all flows
            for (int i=0; i<size; i++) 
                if (taint2_query_ram(paddr+i))
                    taint2_labelset_ram_iter(paddr+i, collect_flow, NULL);            
        }
    }
}

#endif



bool init_plugin(void *self) {

#ifdef CONFIG_SOFTMMU
    
//    panda_require("osi");
//    panda_require("asidstory");
    panda_require("taint2");

    assert(init_taint2_api());
//    assert(init_asidstory_api());
//    assert(init_osi_api());

//    panda_cb pcb;
//    pcb.after_machine_init = ipflow_enable_taint;
//    panda_register_callback(self, PANDA_CB_AFTER_MACHINE_INIT, pcb);
    
//    pcb.before_block_exec = getprocessandlibs;
//   panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

//    PPP_REG_CB("taint2", on_after_store, ipflow_store);
    PPP_REG_CB("taint2", on_after_load, taint_mmio_load);

    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();

    // Enable memory logging -- this makes the on_after_load and on_after_store callbacks function
    panda_enable_memcb();

    return true;

#else
    fprintf(stderr, "taint_mmio doesnt support user mode\n");
    return false;
#endif
}


void uninit_plugin(void *self) {
#if 0 

    stringstream ss;

    ss << \
"<!doctype html>\n"
"<html>\n"
"<head>\n"
"  <title>Network | Basic usage</title>\n"
"  <script type='text/javascript' src='http://visjs.org/dist/vis.js'></script>\n"
"  <link href='http:////visjs.org/dist/vis-network.min.css' rel='stylesheet' type='text/css' />\n"
"  <style type='text/css'>\n"
"    #mynetwork {\n"
"      width: 1200px;\n"
"      height: 800px;\n"
"      border: 1px solid lightgray;\n"
"    }\n"
"  </style>\n"
"</head>\n"
"<body>\n"
"<p>Inter-process Flow Graph for replay "
<< replay_name << 
"</p>\n"
"<div id='mynetwork'></div>\n"
"<script type='text/javascript'>\n"
;

    ss << "var nodes = new  vis.DataSet([\n";
    for (auto kvp : label2proclib) {
        Tlabel label = kvp.first;
        string proclib = kvp.second;
        ss << "{id : " << label << ", label: '" << proclib << "'},\n";
    }
    ss << "]);\n";
    ss << "var edges = new vis.DataSet([\n";
    for (auto kvp : ipflow) {
        IpFlow ipf = kvp.first;
        ss << "{from: " << ipf.from_label << ", to: " << ipf.to_label << ", 'arrows': 'to', 'physics': false, 'smooth': false},\n";
    }
    ss << "]);\n";

    ss << \
"  var container = document.getElementById('mynetwork');\n"
"  var data = {\n"
"    nodes: nodes,\n"
"    edges: edges\n"
"  };\n"
"  var options = {};\n"
"  var network = new vis.Network(container, data, options);\n"
"</script>\n"
"</body>\n"
"</html>\n";
;

ofstream ipgfile;
string ipgfname = string(replay_name) + "-igp.html";
ipgfile.open(ipgfname);
ipgfile << ss.str();
ipgfile.close();



for (auto kvp:label2proclib) {
    Tlabel l = kvp.first;
    string proclib = kvp.second;
    cout << "Label " << l << " " << proclib << "\n";
    
}

for (auto kvp:ipflow) {
    IpFlow ipf = kvp.first;
    IpfStats s = kvp.second;
    cout << "Flow " << label2proclib[ipf.from_label] << " -> " << label2proclib[ipf.to_label] << " : ";
    cout << " count=" << s.count << " [" << s.first_instr << ".." << s.last_instr << "\n";
}

#endif
}
