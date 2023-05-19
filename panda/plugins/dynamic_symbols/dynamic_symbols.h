#pragma once
#include <linux/elf.h>
#include <linux/auxvec.h>
#include <iostream> 
#include <vector>
#include <string>
#include <iterator> 
#include <map> 
#include <set>
#include <algorithm>
#include "panda/plugin.h"
#include "osi/osi_types.h"
#include "osi/osi_ext.h"
#include "osi/os_intro.h"
#include <unordered_map>
#include <unordered_set>
#include "osi_linux/endian_helpers.h"
#include "hw_proc_id/hw_proc_id_ext.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
    #include "dynamic_symbols_int_fns.h"
    #include "hooks/hooks_int_fns.h"
    #include "syscalls2/syscalls_ext_typedefs.h"
    #include "syscalls2/syscalls2_info.h"
    #include "syscalls2/syscalls2_ext.h"
    #include "proc_start_linux/proc_start_linux.h"
    #include "proc_start_linux/proc_start_linux_ppp.h"
}
using namespace std;

// local includes
#include "util.h"
#include "arch_info.h"
#define error_case(A,B,C) // printf("%s %s %s\n", A, B, C)

typedef target_ulong ASID;
typedef target_ulong BASE;

enum AnalysisType {
    ANALYSIS_SPECIFIC, // we have a reason to think things might chane
    ANALYSIS_GENERIC, // we don't have a reason to think things might change
};

enum AsidState {
    ASID_STATE_UNKNOWN,
    ASID_STATE_SUCCESS,
    ASID_STATE_FAIL,
};


void enable_analysis(enum AnalysisType type);
bool initialize_process_infopoints(void* self);
void remove_asid_entries(target_ulong asid);



inline bool operator<(const struct symbol& s, const struct symbol& p){
    return s.address < p.address;
}

inline bool operator<(const struct symbol& s, target_ulong p){
    return s.address < p;
}

inline bool operator<(const hook_symbol_resolve &s, const hook_symbol_resolve &p){
    return tie(s.cb,s.hook_offset,s.offset)  < tie(p.cb,p.hook_offset,p.offset);
}

inline bool operator<(const pair<string, target_ulong>& s, const pair<string, target_ulong>& p){
    int s_comp = s.first.compare(p.first);
    if(s_comp == 0){
        return s.second < p.second;
    }
    return s_comp;
}

void bind_symbol(CPUState *cpu, char* name, target_ulong m, struct symbol *s, target_ulong pltgot, target_ulong mips_local_gotno, target_ulong mips_gotsym_idx);


// https://stackoverflow.com/questions/32685540/why-cant-i-compile-an-unordered-map-with-a-pair-as-key
// Only for pairs of std::hash-able types for simplicity.
// You can of course template this struct to allow other hash functions
struct pair_hash {
    template <class T1, class T2>
    std::size_t operator () (const std::pair<T1,T2> &p) const {
        auto h1 = std::hash<T1>{}(p.first);
        auto h2 = std::hash<T2>{}(p.second);
        return h1 ^ h2;  
    }
};

class Library{
public:
    string name;
    target_ulong pltgot;
    target_ulong mips_local_gotno;
    target_ulong mips_gotsym_idx;
    unordered_map<string, struct symbol> symbols;

    void bind_all(CPUState *cpu, target_ulong base){
        for(auto &s : symbols){
            bind_symbol(cpu, (char*)name.c_str(), base, &s.second, pltgot, mips_local_gotno, mips_gotsym_idx);
        }
    }
    void bind(CPUState *cpu, target_ulong base, char *symname){
        auto it = symbols.find(symname);
        if (it != symbols.end()){
            bind_symbol(cpu, (char*)name.c_str(), base, &it->second, pltgot, mips_local_gotno, mips_gotsym_idx);
        }
    }
};