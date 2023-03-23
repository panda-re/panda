/* PANDABEGINCOMMENT
 * 
 * Authors:
 * Luke Craig               luke.craig@ll.mit.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

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

map<target_ulong, map<string, target_ulong>> mapping;

#define error_case(A,B,C) // printf("%s %s %s\n", A, B, C)

#if TARGET_LONG_BITS == 32
#define ELF(r) Elf32_ ## r
#define ELFD(r) ELF32_ ## r
#else
#define ELF(r) Elf64_ ## r
#define ELFD(r) ELF64_ ## r
#endif

#define DT_INIT_ARRAY	   25		  ,  /* Array with addresses of init fct */
#define DT_FINI_ARRAY	   26		  ,  /* Array with addresses of fini fct */
#define DT_INIT_ARRAYSZ	   27		  ,  /* Size in bytes of DT_INIT_ARRAY */
#define DT_FINI_ARRAYSZ	   28		  ,  /* Size in bytes of DT_FINI_ARRAY */
#define DT_RUNPATH	       29		  ,  /* Library search path */
#define DT_FLAGS	      30		  ,  /* Flags for the object being loaded */
#define DT_PREINIT_ARRAY  32		  ,  /* Array with addresses of preinit fct*/
#define DT_PREINIT_ARRAYSZ 33		  ,  /* size in bytes of DT_PREINIT_ARRAY */
#define DT_NUM		      34		  ,  /* Number used */
#define DT_SUNW_RTLDINF 0x6000000e
#define DT_CONFIG 0x6ffffefa
#define DT_DEPAUDIT 0x6ffffefb
#define DT_AUDIT 0x6ffffefc
#define DT_PLTPAD 0x6ffffefd
#define DT_MOVETAB 0x6ffffefe
#define DT_SYMINFO 0x6ffffeff
#define DT_GNU_HASH 0x6FFFFEF5

void* self_ptr;
panda_cb pcb_asid;
panda_cb pcb_bbt;
panda_cb pcb_btc_execve;
panda_cb before_block_translate_hook_adder_callback;

vector<int> possible_tags{ DT_PLTGOT , DT_HASH , DT_STRTAB , DT_SYMTAB , DT_RELA , DT_INIT , DT_FINI , DT_REL , DT_DEBUG , DT_JMPREL, 25, 26, 32, DT_SUNW_RTLDINF , DT_CONFIG , DT_DEPAUDIT , DT_AUDIT , DT_PLTPAD , DT_MOVETAB , DT_SYMINFO , DT_VERDEF , DT_VERNEED };


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

// [section name, address] -> map of symbol name to symbols 
unordered_map<pair<target_ulong,string>, unordered_map<string,struct symbol>, pair_hash> seen_libraries;
// these are section names we've tried and confirmed are not libraries
unordered_set<string> seen_nonlibraries;
// asid -> section_name ->  symbols map pointer
unordered_map<target_ulong, unordered_map<string, unordered_map<string,struct symbol>*>> symbols;

// section -> set of structs
// section -> name -> set struct
unordered_map<string, unordered_map<string, set<struct hook_symbol_resolve>>> hooks; 
//set<struct hook_symbol_resolve> hooks;

void (*dlsym_add_hook)(struct hook*);
void (*dlsym_hooks_flush_pc)(target_ulong pc);

void hook_symbol_resolution(struct hook_symbol_resolve *h){
    // ISSUE: Doesn't resolve for hooks that have been previously resolved.
    //printf("adding hook \"%s\" \"%s\" %llx\n", h->section, h->name, (long long unsigned int) h->cb);
    string section(h->section);
    string name(h->name);
    hooks[section][name].insert(*h);
}


void new_assignment_check_symbols(CPUState* cpu, char* procname, unordered_map<string, struct symbol> ss, OsiModule* m){
    string module(m->name);
    vector<tuple<struct hook_symbol_resolve, struct symbol, OsiModule>> symbols_to_flush;

    set<string> matching_libs;
    matching_libs.insert("");

    for (auto strs : hooks){
        string lib = strs.first;
        auto h = strs.second;
        if (!h.empty() && module.find(lib) != std::string::npos && !module.empty()){
            matching_libs.insert(lib);
        }
    }

    for (string lib : matching_libs){
        for (auto symbol_matcher : hooks[lib]){
            string symname = symbol_matcher.first;
            set<struct hook_symbol_resolve> h = symbol_matcher.second;
            for (auto hook_candidate: h){
                if (hook_candidate.enabled){
                    if (symname.empty()){
                        if (hook_candidate.hook_offset){
                            struct symbol s;
                            memset(&s, 0, sizeof(struct symbol));
                            s.address = m->base + hook_candidate.offset;
                            strncpy((char*)&s.section, m->name, sizeof(s.section)-2);
                            symbols_to_flush.push_back(make_tuple(hook_candidate,s, *m));
                        }else{
                            for (auto sym: ss){
                                symbols_to_flush.push_back(make_tuple(hook_candidate, sym.second, *m));
                            }
                        }
                    }else{
                        auto it = ss.find(symname);
                        if (it != ss.end()){
                            auto a = *it;
                            symbols_to_flush.push_back(make_tuple(hook_candidate, a.second, *m));
                        }
                    }
                }
            }
        }
    }
    if (!symbols_to_flush.empty()){
        //panda_do_flush_tb();
        // printf("%s hooking %d symbols in %s\n", procname, (int)symbols_to_flush.size(), m->name);
    }
    while (!symbols_to_flush.empty()){
        auto p = symbols_to_flush.back();
        auto hook_candidate = get<0>(p);
        auto s = get<1>(p);
        auto m = get<2>(p);
        (*(hook_candidate.cb))(cpu, &hook_candidate, s, &m);
        symbols_to_flush.pop_back();
    }
    //printf("finished adding symbols for %s:%s\n", procname, m->name);
}

struct symbol resolve_symbol(CPUState* cpu, target_ulong asid, char* section_name, char* symbol){
    update_symbols_in_space(cpu);

    for (const auto &section : symbols[asid]){
        string n = section.first;
        auto section_vec = section.second;
        size_t found;
        if (section_name == NULL){
            found = 0;
        }else{
            found = n.find(section_name); 
        }
        //section name is A "does string exist in section"
        if (found != string::npos){
            string sym(symbol);
            auto it = section_vec->find(sym);
            if (it != section_vec->end()){
                struct symbol val = it->second;
                string val_str (val.name);
                strncpy((char*) &val.section, section.first.c_str(), sizeof(val.section) -2);
                return val;
            }
        } 
    }
    struct symbol blank;
    blank.address = 0;
    memset((char*) & blank.name, 0, MAX_PATH_LEN);
    memset((char*) & blank.section, 0, MAX_PATH_LEN);
    return blank;
}

struct symbol get_best_matching_symbol(CPUState* cpu, target_ulong address, target_ulong asid){
    update_symbols_in_space(cpu);
    struct symbol best_candidate;
    best_candidate.address = 0;
    memset((char*) & best_candidate.name, 0, MAX_PATH_LEN);
    memset((char*) & best_candidate.section, 0, MAX_PATH_LEN);
    for (const auto& section : symbols[asid]){
        unordered_map<string, struct symbol> section_symbols = *section.second;
        for (auto i : section_symbols){
            struct symbol it = i.second;
            if (it.address > address){
                if (it.address == address){
                    // if we found a match just break and move on.
                    memcpy(&best_candidate, &it, sizeof(struct symbol));
                    break;
                }
                if (it.address > best_candidate.address){
                    //copy it
                    memcpy(&best_candidate, &it, sizeof(struct symbol));
                }
            }
        }
    }
    return best_candidate;
}

string read_str(CPUState* cpu, target_ulong ptr){
    string buf = "";
    char tmp;
    while (true){
        if (panda_virtual_memory_read(cpu, ptr, (uint8_t*)&tmp,1) == MEMTX_OK){
            buf += tmp;
            if (tmp == '\x00'){
                break;
            }
            ptr+=1;
        }else{
            break;
        }
    }
    return buf;
}

int get_numelements_hash(CPUState* cpu, target_ulong dt_hash){
    //printf("in dt_hash_section 0x%llx\n", (long long unsigned int) dt_hash);
    struct dt_hash_section dt;

    if (panda_virtual_memory_read(cpu, dt_hash, (uint8_t*) &dt, sizeof(struct dt_hash_section))!= MEMTX_OK){
        //printf("got error 2\n");
        return -1;
    }
    fixupendian(dt.nbuckets);
    //printf("Nbucks: 0x%x\n", dt.nbuckets);
    return dt.nbuckets;
}

int get_numelements_gnu_hash(CPUState* cpu, target_ulong gnu_hash){
    //printf("Just DT_HASH with %s\n", name.c_str());
    // must do gnu_hash method
    // see the following for details:
    // http://deroko.phearless.org/dt_gnu_hash.txt
    // https://flapenguin.me/elf-dt-gnu-hash

    struct gnu_hash_table ght;
    if (panda_virtual_memory_read(cpu, gnu_hash, (uint8_t*)&ght, sizeof(ght))!=MEMTX_OK){
        //printf("got error in gnu_hash_table\n");
        return -1;
    }
    //printf("GNU numbucks: 0x%x, bloom_size 0x%x\n", ght.nbuckets, ght.bloom_size);
    uint32_t* buckets = (uint32_t*) malloc(ght.nbuckets*sizeof(uint32_t));
    assert(buckets != NULL);

    target_ulong bucket_offset = gnu_hash + sizeof(gnu_hash_table) + (ght.bloom_size*sizeof(target_ulong));

    if (panda_virtual_memory_read(cpu, bucket_offset, (uint8_t*) buckets, ght.nbuckets*sizeof(uint32_t)) != MEMTX_OK){
        //printf("Couldn't read buckets\n");
        free(buckets);
        return -1;
    }

    unsigned int last_sym = 0;
    int index = 0;
    for (index = 0; index < ght.nbuckets; index++){
        //printf("%d %x\n", index, buckets[index]);
        if (buckets[index] > last_sym){
            last_sym = buckets[index]; 
        }
    }
    //printf("last_sym %x index: %d\n", last_sym, index);
    
    free(buckets);
    
    uint32_t num = 0;

    uint32_t chain_index = last_sym - ght.symoffset;
    target_ulong chain_address = bucket_offset + (sizeof(uint32_t)*ght.nbuckets);

    while (!(num&1)){
        if (panda_virtual_memory_read(cpu, chain_address + (chain_index * sizeof(uint32_t)), (uint8_t*) &num, sizeof(uint32_t))!= MEMTX_OK){                                
            //printf("Failed loading chains\n");
            return -1;
        }
        chain_index++;
    }
    return chain_index + ght.symoffset;
}

int get_numelements_symtab(CPUState* cpu, target_ulong base, target_ulong dt_hash, target_ulong gnu_hash, target_ulong dynamic_section, target_ulong symtab, int numelements_dyn){
    if (base != dt_hash){
        int result = get_numelements_hash(cpu, dt_hash);
        if (result != -1)
            return result;
    }
    if (base != gnu_hash){
        int result = get_numelements_gnu_hash(cpu, gnu_hash);
        if (result != -1)
            return result;
    }
    target_ulong symtab_min = symtab + 0x100000;
    ELF(Dyn) tag;
    for (int j=0; j< numelements_dyn; j++){
        if (panda_virtual_memory_read(cpu, dynamic_section + j*sizeof(ELF(Dyn)), (uint8_t*)&tag, sizeof(ELF(Dyn))) != MEMTX_OK){
            return -1;
        }
        fixupendian(tag.d_tag);
        fixupendian(tag.d_un.d_ptr);
        if (find(begin(possible_tags), end(possible_tags), (int)tag.d_tag) != end(possible_tags)){
            uint32_t candidate = tag.d_un.d_ptr;
            if (candidate > symtab && candidate < symtab_min){
                symtab_min = candidate;
            }
        }
    }
    return (symtab_min - symtab)/(sizeof(ELF(Dyn)));
}



char arr[][20] = {"[heap]", "[stack]", "[vdso]", "[vsyscall]", "[vvar]", "[???]", "ld.so.cache"};


bool should_ignore_section(char *name){
    for (int i=0; i<(sizeof(arr)/sizeof(arr[0])); i++){
        if (strncmp(name, arr[i], strlen(arr[i])) == 0){
            return true;
        }
    }
    return false;
}

bool find_symbols(CPUState* cpu, target_ulong asid, OsiProc *current, OsiModule *m){
    string name(m->name);
    ELF(Ehdr) ehdr;
    ELF(Phdr) dynamic_phdr;
    ELF(Dyn) tag;
    target_ulong strtab = 0, symtab = 0, strtab_size = 0, dt_hash = 0;
    target_ulong symtab_size;
    target_ulong gnu_hash = 0;
    target_ulong phnum, phoff;
    char *symtab_buf, *strtab_buf;
    int numelements_dyn, numelements_symtab;

    if (panda_virtual_memory_read(cpu, m->base, (uint8_t*)&ehdr, sizeof(ELF(Ehdr))) != MEMTX_OK){            
        error_case(current->name, m->name, "3 CNRB");
        // can't read page. try again later;
        return false;
    }

    // is this an ELF?
    if (!(ehdr.e_ident[0] == ELFMAG0 && ehdr.e_ident[1] == ELFMAG1 && ehdr.e_ident[2] == ELFMAG2 && ehdr.e_ident[3] == ELFMAG3)){
        // If we aren't an ELF we don't need to get symbols
        // therefore we return true
        error_case(current->name, m->name, "NOT AN ELF HEADER");
        return true;
    } 
    // is this a shared object?
    uint16_t e_type = ehdr.e_type;
    #if defined(TARGET_WORDS_BIGENDIAN)
    e_type = bswap16(e_type);
    #endif
    if (e_type != ET_DYN){
        // printf("add " TARGET_FMT_lx " %s to seen_nonlibraries\n", asid, m->name);
        seen_nonlibraries.insert(name);
        return true;
    }

    phnum = ehdr.e_phnum;
    phoff = ehdr.e_phoff;
    fixupendian(phnum);
    fixupendian(phoff);

    for (int j=0; j<phnum; j++){
        if (panda_virtual_memory_read(cpu, m->base + phoff + (j*sizeof(ELF(Phdr))), (uint8_t*)&dynamic_phdr, sizeof(ELF(Phdr))) != MEMTX_OK){
            error_case(current->name, m->name, "5 DPHDR");
            return false;
        }
        fixupendian(dynamic_phdr.p_type)
        if (dynamic_phdr.p_type == PT_DYNAMIC){
            break;
        }else if (dynamic_phdr.p_type == PT_NULL){
            error_case(current->name, m->name, "PTNULL");
            //printf("hit PT_NULL\n");
            return false;
        }else if (j == phnum -1){
            error_case(current->name, m->name, "END");
            //printf("hit phnum-1\n");
            return false;
        }
    }
    
    fixupendian(dynamic_phdr.p_filesz);
    numelements_dyn = dynamic_phdr.p_filesz / sizeof(ELF(Dyn));
    // iterate over dynamic program headers and find strtab
    // and symtab
    int j = 0;

    fixupendian(dynamic_phdr.p_vaddr);
    while (j < numelements_dyn){
        if (panda_virtual_memory_read(cpu, m->base + dynamic_phdr.p_vaddr + (j*sizeof(ELF(Dyn))), (uint8_t*)&tag, sizeof(ELF(Dyn))) != MEMTX_OK){
            //printf("%s:%s Failed to read entry %d\n", name.c_str(), current->name, j);
            error_case(current->name, m->name, "5 DPDR");
            return false;
        }

        fixupendian(tag.d_tag);
        fixupendian(tag.d_un.d_ptr);

        if (tag.d_tag == DT_STRTAB){
            strtab = tag.d_un.d_ptr;
        }else if (tag.d_tag == DT_SYMTAB){
            symtab = tag.d_un.d_ptr;
        }else if (tag.d_tag == DT_STRSZ){
            strtab_size = tag.d_un.d_ptr;
        }else if (tag.d_tag == DT_HASH){
            dt_hash = tag.d_un.d_ptr;
        }else if (tag.d_tag == DT_GNU_HASH){
            gnu_hash = tag.d_un.d_ptr;
        }else if (tag.d_tag == DT_NULL){
            j = numelements_dyn;
        }
        j++;
    }  

    // some of these are offsets. some are fully qualified
    // addresses. this is a gimmick that can sort-of tell.
    // probably better to replace this at some point
    if (strtab < m->base){
        strtab += m->base;
    }
    if (symtab < m->base){
        symtab += m->base;
    }
    if (dt_hash < m->base){
        dt_hash += m->base;
    }
    if (gnu_hash < m->base){
        gnu_hash += m->base;
    }

    numelements_symtab = get_numelements_symtab(cpu,m->base, dt_hash, gnu_hash, m->base + dynamic_phdr.p_vaddr, symtab, numelements_dyn);
    if (numelements_symtab == -1){
        error_case(current->name, m->name, "6 GETELEMENTSSYMTAB");
        return false;
    }

    symtab_size = numelements_symtab * sizeof(ELF(Sym));
    symtab_buf = (char*)malloc(symtab_size);
    strtab_buf = (char*)malloc(strtab_size);
    
    if (panda_virtual_memory_read(cpu, symtab, (uint8_t*)symtab_buf, symtab_size) != MEMTX_OK){
        error_case(current->name, m->name, "8 CNR SYMTAB");
        free(symtab_buf);
        free(strtab_buf);
        return false;
    }
    if (panda_virtual_memory_read(cpu, strtab, (uint8_t*) strtab_buf, strtab_size) != MEMTX_OK){
        error_case(current->name, m->name, "7 CNR STRTAB");
        free(symtab_buf);
        free(strtab_buf);
        return false;
    }

    pair<target_ulong, string> c(m->base, name);
    for (int i=0;i<numelements_symtab; i++){
        ELF(Sym)* a = (ELF(Sym)*) (symtab_buf + i*sizeof(ELF(Sym)));
        fixupendian(a->st_name);
        fixupendian(a->st_value);
        fixupendian(a->st_info);

        if (a->st_name < strtab_size && a->st_value != 0){
            struct symbol s;
            strncpy((char*)&s.name, &strtab_buf[a->st_name], sizeof(s.name)-2);
            strncpy((char*)&s.section, m->name, sizeof(s.section)-2);
            // s.bind = ELFD(ST_BIND)(a->st_info);
            // s.type = ELFD(ST_TYPE)(a->st_info);
            // int r_type = ELFD(R_TYPE)(a->st_info);
            s.address = m->base + a->st_value;
#ifdef TARGET_ARM
            s.address &= ~0x1;
#endif
            // if (s.type != 2)
            //  printf("found symbol %s %s 0x%llx %d %d %d\n",s.section, &strtab_buf[a->st_name],(long long unsigned int)s.address, s.bind, s.type, r_type);
            string sym_name(s.name);
            seen_libraries[c][sym_name] = s;
        }
    }
    if (seen_libraries[c].size() > 0){
        symbols[asid][name] = &seen_libraries[c];
        new_assignment_check_symbols(cpu, current->name, seen_libraries[c], m);
        error_case(current->name, m->name, "SUCCESS");
        // printf("Successful on %s. Found %d symbols " TARGET_FMT_lx "\n", m->name, (int)seen_libraries[c].size(), m->base);
    }
    free(symtab_buf);
    free(strtab_buf);
    return true;
}


bool update_symbols_in_space(CPUState* cpu){
    OsiProc *current;
    OsiModule *m;
    target_ulong asid;
    GArray *ms;
    unordered_map<string, OsiModule*> lowest_library_entry;
    bool none_missing;

    if (panda_in_kernel(cpu)){
        return false;
    }
    if (!id_is_initialized()){
        return false;
    }
    asid = get_id(cpu);
    current = get_current_process(cpu);
    if (current == NULL){
        return false;
    }
    ms = get_mappings(cpu, current);
    if (ms == NULL) {
        return false;
    }

    //iterate over mappings and find the lowest VA for each relevant library
    for (int i = 0; i < ms->len; i++) {
        m = &g_array_index(ms, OsiModule, i);
        // printf("mapping name: %s base: " TARGET_FMT_lx "\n", m->name, m->base);
        if (m->name == NULL){
            continue;
        }
        if (should_ignore_section(m->name)){
            continue;
        }
        if (strstr(m->name, ".so") != NULL){
            // we already read this one
            if (symbols[asid].find(m->name) != symbols[asid].end() && symbols[asid][m->name]->size() > 0){
                // error_case(current->name, m->name, " in symbols[asid] already and has");
                continue;
            }

            if (seen_nonlibraries.find(m->name) != seen_nonlibraries.end()){
                // error_case(current->name, m->name, " in seen_nonlibraries[asid] already");
                continue;
            }
            pair<target_ulong, string> candidate(m->base, m->name);
            if (seen_libraries.find(candidate) != seen_libraries.end()) {
                // printf("COPY %s:%s for asid " TARGET_PTR_FMT "  and base of " TARGET_PTR_FMT "\n",  current->name, m->name, get_id(cpu), m->base);
                symbols[asid][m->name] = &seen_libraries[candidate];
                new_assignment_check_symbols(cpu, current->name, seen_libraries[candidate], m);
                continue;
            }
            if (!find_symbols(cpu, asid, current,m)){
                none_missing = false;
            }
        }
    }
    return none_missing;
}

void bbt(CPUState *env, target_ulong pc){
    if (update_symbols_in_space(env)){
        panda_disable_callback(self_ptr, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb_bbt);
    }
}
void sys_mmap_return(
    CPUState* cpu,
    target_ulong pc,
    target_ulong arg0,
    target_ulong arg1,
    target_ulong arg2,
    target_ulong arg3,
    target_ulong arg4,
    target_ulong arg5)
{
    panda_enable_callback(self_ptr, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb_bbt);
}

void sys_mmap2_return(CPUState* cpu, target_ulong pc, unsigned int b, unsigned int c, int d, int e, int f, unsigned int g){
    panda_enable_callback(self_ptr, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb_bbt);
}

void sys_mmap_arm64_return(CPUState* cpu, target_ulong pc, long unsigned int b, unsigned int c, int d, int e, int f, long unsigned int g){
    panda_enable_callback(self_ptr, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb_bbt);
}

void sys_mmap_mips_return(CPUState* cpu, target_ulong pc, unsigned int b, unsigned int c, int d, int e, int f, unsigned int g){
    panda_enable_callback(self_ptr, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb_bbt);
}

void sys_exit_enter(CPUState *cpu, target_ulong pc, int exit_code){
    target_ulong asid = get_id(cpu);
    symbols.erase(asid);
    panda_enable_callback(self_ptr, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb_bbt);
}

bool asid_changed(CPUState *env, target_ulong old_asid, target_ulong new_asid) {
    panda_enable_callback(self_ptr, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb_bbt);
    return false;
}

void hook_program_start(CPUState *env, TranslationBlock* tb, struct hook* h){
    panda_enable_callback(self_ptr, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb_bbt);
    h->enabled = false;
}

void recv_auxv(CPUState *env, TranslationBlock *tb, struct auxv_values *av){
    target_ulong asid = get_id(env);
    symbols.erase(asid);
    struct hook h;

#ifdef TARGET_ARM
    // If the entrypoint is in thumb mode, bit 0 will be set which results
    // in an update to the CSPR.T bit. The hook needs needs the bit to masked
    // out.
    h.addr = av->entry & ~0x1;
#else
    h.addr = av->entry;
#endif

    h.asid = asid;
    h.type = PANDA_CB_START_BLOCK_EXEC;
    h.cb.start_block_exec = hook_program_start;
    h.km = MODE_USER_ONLY;
    h.enabled = true;
    dlsym_add_hook(&h);

    panda_enable_callback(self_ptr, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb_bbt);
}

bool init_plugin(void *self) {
    self_ptr = self;
    pcb_asid.asid_changed = asid_changed;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb_asid);
    pcb_bbt.before_block_translate = bbt;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb_bbt);
    panda_disable_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb_bbt);

    panda_require("osi");
    assert(init_osi_api());
    panda_require("hw_proc_id");
    assert(init_hw_proc_id_api());
    panda_require("proc_start_linux");
    PPP_REG_CB("proc_start_linux",on_rec_auxv, recv_auxv);
    #if defined(TARGET_PPC)
        fprintf(stderr, "[ERROR] dynamic_symbols: PPC architecture not supported by syscalls2!\n");
        return false;
    #else
        // why? so we don't get 1000 messages telling us syscalls2 is already loaded
        void* syscalls2 = panda_get_plugin_by_name("syscalls2");
        if (syscalls2 == NULL){
            panda_require("syscalls2");
        }
        assert(init_syscalls2_api());
        PPP_REG_CB("syscalls2", on_sys_exit_enter, sys_exit_enter);
        PPP_REG_CB("syscalls2", on_sys_exit_group_enter, sys_exit_enter);
        PPP_REG_CB("syscalls2", on_sys_exit_enter, sys_exit_enter);
        PPP_REG_CB("syscalls2", on_sys_exit_group_enter, sys_exit_enter);
#if defined(TARGET_X86_64)
    PPP_REG_CB("syscalls2", on_sys_mmap_return, sys_mmap_return);
#elif defined(TARGET_ARM) && defined(TARGET_AARCH64)
    PPP_REG_CB("syscalls2", on_sys_mmap_return, sys_mmap_arm64_return);
#elif defined(TARGET_I386)
    PPP_REG_CB("syscalls2", on_sys_mmap_pgoff_return, sys_mmap_return);
#elif defined(TARGET_ARM)
    PPP_REG_CB("syscalls2", on_do_mmap2_return, sys_mmap_return);
#elif defined(TARGET_MIPS)
    PPP_REG_CB("syscalls2", on_mmap2_return, sys_mmap_mips_return);
#endif
    #endif
    void* hooks = panda_get_plugin_by_name("hooks");
    if (hooks == NULL){
        panda_require("hooks");
        hooks = panda_get_plugin_by_name("hooks");
    }
    if (hooks != NULL){
        dlsym_add_hook = (void(*)(struct hook*)) dlsym(hooks, "add_hook");
        dlsym_hooks_flush_pc = (void(*)(target_ulong pc)) dlsym(hooks, "hooks_flush_pc");
        if ((void*)dlsym_add_hook == NULL) {
            printf("couldn't load add_hook from hooks\n");
            return false;
        }
    }
    return true;
}

void uninit_plugin(void *self) {}
