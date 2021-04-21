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
#include "osi_linux/endian_helpers.h"


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

#if TARGET_LONG_BITS == 32
#define ELF(r) Elf32_ ## r
#else
#define ELF(r) Elf64_ ## r
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


void new_assignment_check_symbols(CPUState* cpu, unordered_map<string, struct symbol> ss, OsiModule* m){
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
        //printf("%s hooking %d symbols in %s\n", procname, (int)symbols_to_flush.size(), m->name);
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

    for (const auto section : symbols[asid]){
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
        //goto nextloop;
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
    //printf("Get numelembs symtab 0x%x, 0x%x\n", base, dt_hash);
    if (base != dt_hash){
        int result = get_numelements_hash(cpu, dt_hash);
        if (result != -1)
            return result;
    }
    if (base != gnu_hash){
        //printf("trying gnu_hash\n");
        int result = get_numelements_gnu_hash(cpu, gnu_hash);
        if (result != -1)
            return result;
    }
    // we don't actually have the size of these things 
    // (not included) so we find it by finding the next
    // closest section
    //  target_ulong strtab_min = strtab + 0x100000;
    //printf("continuing onto the end\n");
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

#define error_case(A,B,C) //printf("%s %s %s\n", A, B, C)

void helper(){};


void find_symbols(CPUState* cpu, target_ulong asid, OsiProc *current, OsiModule *m){
    if (m->name == NULL){
        error_case(current->name, m->name, "m->name is NULL");
        return;
    }
    string name(m->name);

    // we already read this one
    if (symbols[asid].find(name) != symbols[asid].end() && symbols[asid][name]->size() > 0){
        error_case(current->name, m->name, " in symbols[asid] already and has");
        //printf("%s %s already exists \n", current->name, m->name);
        return;
    }

    pair<target_ulong, string> candidate(m->base, name);

    auto it = seen_libraries.find(candidate);
    if (it != seen_libraries.end()) {
        //printf("COPY %s:%s for asid " TARGET_PTR_FMT "  and base of " TARGET_PTR_FMT "\n",  current->name, m->name, panda_current_asid(cpu), m->base);
        //printf("size of ASID before is %d\n", (int)symbols[asid].size());
        symbols[asid][name] = &seen_libraries[candidate];
        //printf("size of ASID after is %d\n", (int)symbols[asid].size());
        new_assignment_check_symbols(cpu, seen_libraries[candidate], m);
        return;
    }
    // static variable to store first 4 bytes of mapping
    char elf_magic[4];

    // read first 4 bytes
    if (likely(panda_virtual_memory_read(cpu, m->base, (uint8_t*)elf_magic, 4) != MEMTX_OK)){            
        error_case(current->name, m->name, "3 CNRB");
        // can't read page.
        return;
    }
    // is it an ELF header?
    if (unlikely(elf_magic[0] == '\x7f' && elf_magic[1] == 'E' && elf_magic[2] == 'L' && elf_magic[3] == 'F')){
        ELF(Ehdr) ehdr;
        // attempt to read memory allocation
        if (panda_virtual_memory_read(cpu, m->base, (uint8_t*)&ehdr, sizeof(ELF(Ehdr))) != MEMTX_OK){
            error_case(current->name, m->name, "4 CNREH");
            //printf("cant read elf header\n");
            return;
        }


        target_ulong phnum = ehdr.e_phnum;
        target_ulong phoff = ehdr.e_phoff;
        fixupendian(phnum);
        fixupendian(phoff);

        ELF(Phdr) dynamic_phdr;

        //printf("Read Phdr from 0x%x + 0x%x + j*0x%lx\n", m->base, phoff, (sizeof(ELF(Phdr))));

        for (int j=0; j<phnum; j++){
            if (panda_virtual_memory_read(cpu, m->base + phoff + (j*sizeof(ELF(Phdr))), (uint8_t*)&dynamic_phdr, sizeof(ELF(Phdr))) != MEMTX_OK){
                error_case(current->name, m->name, "5 DPHDR");
                return;
            }

            fixupendian(dynamic_phdr.p_type)

            if (dynamic_phdr.p_type == PT_DYNAMIC){
                break;
            }else if (dynamic_phdr.p_type == PT_NULL){
                error_case(current->name, m->name, "PTNULL");
                //printf("hit PT_NULL\n");
                return;
            }else if (j == phnum -1){
                error_case(current->name, m->name, "END");
                //printf("hit phnum-1\n");
                return;
            }
        }
        fixupendian(dynamic_phdr.p_filesz);
        int numelements_dyn = dynamic_phdr.p_filesz / sizeof(ELF(Dyn));
        // iterate over dynamic program headers and find strtab
        // and symtab
        ELF(Dyn) tag;
        target_ulong strtab = 0, symtab = 0, strtab_size = 0, dt_hash = 0, gnu_hash = 0;
        int j = 0;

        fixupendian(dynamic_phdr.p_vaddr);
        while (j < numelements_dyn){
            //printf("Read Dyn PHDR from 0x%x + 0x%x + j*0x%lx\n", m->base, dynamic_phdr.p_vaddr, (sizeof(ELF(Phdr))));
            if (panda_virtual_memory_read(cpu, m->base + dynamic_phdr.p_vaddr + (j*sizeof(ELF(Dyn))), (uint8_t*)&tag, sizeof(ELF(Dyn))) != MEMTX_OK){
                //printf("%s:%s Failed to read entry %d\n", name.c_str(), current->name, j);
                error_case(current->name, m->name, "5 DPDR");
                return;
            }

            fixupendian(tag.d_tag);
            fixupendian(tag.d_un.d_ptr);

            if (tag.d_tag == DT_STRTAB){
                //printf("Found DT_STRTAB\n");
                strtab = tag.d_un.d_ptr;
            }else if (tag.d_tag == DT_SYMTAB){
                //printf("Found DT_SYMTAB\n");
                symtab = tag.d_un.d_ptr;
            }else if (tag.d_tag == DT_STRSZ ){
                //printf("Found DT_STRSZ\n");
                strtab_size = tag.d_un.d_ptr;
            }else if (tag.d_tag == DT_HASH){
                //printf("Found DT_HASH\n");
                dt_hash = tag.d_un.d_ptr;
            }else if (tag.d_tag == DT_GNU_HASH){
                //printf("Found DT_GNU_HASH\n");
                gnu_hash = tag.d_un.d_ptr;
            }else if (tag.d_tag == DT_NULL){
                //printf("Found DT_NULL \n");
                j = numelements_dyn;
                //break;
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

        //printf("strtab: %llx symtab: %llx hash: %llx\n", (long long unsigned int) strtab, (long long unsigned int)symtab, (long long unsigned int) dt_hash);

        int numelements_symtab = get_numelements_symtab(cpu,m->base, dt_hash, gnu_hash, m->base + dynamic_phdr.p_vaddr, symtab, numelements_dyn);
        if (numelements_symtab == -1){
            error_case(current->name, m->name, "6 GETELEMENTSSYMTAB");
            //printf("numelements_symtab not working\n");
            return;
        }

        target_ulong symtab_size = numelements_symtab * sizeof(ELF(Sym));

        //printf("symtab_size %llx strtab_size %llx\n",(long long unsigned int)symtab_size, (long long unsigned int)strtab_size);

        char* symtab_buf = (char*)malloc(symtab_size);
        char* strtab_buf = (char*)malloc(strtab_size);

        //printf("symtab %llx\n", (long long unsigned int) symtab);
        //printf("symtab: 0x" TARGET_FMT_lx "  0x" TARGET_FMT_lx "\n", symtab, strtab);
        if (panda_virtual_memory_read(cpu, symtab, (uint8_t*)symtab_buf, symtab_size) == MEMTX_OK){
                if (panda_virtual_memory_read(cpu, strtab, (uint8_t*) strtab_buf, strtab_size) == MEMTX_OK){
                int i = 0; 
                //for (int idx =0; idx < strtab_size; idx++)
                //  printf("Strtab[%d]: %c\n", idx, strtab_buf[idx]);

                pair<target_ulong, string> c(m->base, name);

                for (;i<numelements_symtab; i++){
                    ELF(Sym)* a = (ELF(Sym)*) (symtab_buf + i*sizeof(ELF(Sym)));
                    fixupendian(a->st_name);
                    fixupendian(a->st_value);
                    if (a->st_name < strtab_size && a->st_value != 0){
                        struct symbol s;
                        strncpy((char*)&s.name, &strtab_buf[a->st_name], sizeof(s.name)-2);
                        strncpy((char*)&s.section, m->name, sizeof(s.section)-2);
                        s.address = m->base + a->st_value;
                        //printf("found symbol %s %s 0x%llx\n",s.section, &strtab_buf[a->st_name],(long long unsigned int)s.address);
                        string sym_name(s.name);
                        seen_libraries[c][sym_name] = s;
                    }
                }
                if (seen_libraries[c].size() > 0){
                    symbols[asid][name] = &seen_libraries[c];
                    new_assignment_check_symbols(cpu, seen_libraries[c], m);
                    error_case(current->name, m->name, "SUCCESS");
                    //printf("Successful on %s. Found %d symbols " TARGET_FMT_lx "\n", m->name, (int)seen_libraries[c].size(), m->base);
                }
                //printf("CURRENT PC: %llx\n", (long long unsigned int) panda_current_pc(cpu));
            }else{
                error_case(current->name, m->name, "7 CNR STRTAB");
            }
        }else{
            error_case(current->name, m->name, "8 CNR SYMTAB");
        }
        free(symtab_buf);
        free(strtab_buf);
        return;
    }
    error_case(current->name, m->name, "NOT AN ELF HEADER");
}


void update_symbols_in_space(CPUState* cpu){
    if (panda_in_kernel(cpu)){
        return;
    }
    OsiProc *current = get_current_process(cpu);
    target_ulong asid = panda_current_asid(cpu);
    GArray *ms = get_mappings(cpu, current);
    if (ms == NULL) {
        return;
    } else {
        //iterate over mappings
        for (int i = 0; i < ms->len; i++) {
            OsiModule *m = &g_array_index(ms, OsiModule, i);
            find_symbols(cpu, asid, current, m);
        }
    }
}

void bbt(CPUState *env, target_ulong pc){
    if (!panda_in_kernel(env)){
        update_symbols_in_space(env);
        panda_disable_callback(self_ptr, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb_bbt);
    }
}

void sys_exit_enter(CPUState *cpu, target_ulong pc, int exit_code){
    target_ulong asid = panda_current_asid(cpu);
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
    target_ulong asid = panda_current_asid(env);
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

    h.asid = panda_current_asid(env);
    h.type = PANDA_CB_BEFORE_TCG_CODEGEN;
    h.cb.before_tcg_codegen = hook_program_start;
    h.km = MODE_USER_ONLY;
    h.enabled = true;
    dlsym_add_hook(&h);
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

void uninit_plugin(void *self) { 
}
