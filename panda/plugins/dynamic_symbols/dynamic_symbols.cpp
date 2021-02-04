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


// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
#include "hooks/hooks_int_fns.h"
#include "dynamic_symbols_int_fns.h"
#include "syscalls2/syscalls_ext_typedefs.h"
#include "syscalls2/syscalls2_info.h"
#include "syscalls2/syscalls2_ext.h"

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

vector<int> possible_tags{ DT_PLTGOT , DT_HASH , DT_STRTAB , DT_SYMTAB , DT_RELA , DT_INIT , DT_FINI , DT_REL , DT_DEBUG , DT_JMPREL, 25, 26, 32, DT_SUNW_RTLDINF , DT_CONFIG , DT_DEPAUDIT , DT_AUDIT , DT_PLTPAD , DT_MOVETAB , DT_SYMINFO , DT_VERDEF , DT_VERNEED };

inline bool operator<(const struct symbol& s, const struct symbol& p){
    return s.address < p.address;
}

inline bool operator<(const struct symbol& s, target_ulong p){
    return s.address < p;
}

unordered_map<target_ulong, unordered_map<string, set<struct symbol>>> symbols;



vector<struct hook_symbol_resolve> hooks;

void hook_symbol_resolution(struct hook_symbol_resolve *h){
    printf("adding hook %s %llx\n", h->name, (long long unsigned int) h->cb);
    hooks.push_back(*h);
}

void check_symbol_for_hook(CPUState* cpu, struct symbol s, OsiModule *m){
    for (struct hook_symbol_resolve &hook_candidate : hooks){
        if (hook_candidate.enabled){
            //printf("comparing \"%s\" and \"%s\"\n", hook_candidate.name, s.name);
            if (strncmp(s.name, hook_candidate.name, MAX_PATH_LEN -1) == 0){
                //printf("name matches\n");
                if (hook_candidate.section[0] == 0 || strstr(s.section, hook_candidate.section) != NULL){
                    (*(hook_candidate.cb))(cpu, &hook_candidate, s, m);
                }
            }
        }
    }
}

struct symbol resolve_symbol(CPUState* cpu, target_ulong asid, char* section_name, char* symbol){
    update_symbols_in_space(cpu);
    auto proc_mapping = symbols[asid];

    for (const auto& section : proc_mapping){
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
            for (auto &it: section_vec){
                struct symbol val = it;
                string val_str (val.name);
                // symbol resolves on exact equality
                if (val_str.compare(symbol) == 0){
                    //printf("result: %s %s\n", section.first.c_str(), val.name);
                    strncpy((char*) &val.section, section.first.c_str(), MAX_PATH_LEN -1);
                    return val;
                }
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
    auto proc_mapping = symbols[asid];
    struct symbol address_container;
    address_container.address = address;
    struct symbol best_candidate;
    best_candidate.address = 0;
    memset((char*) & best_candidate.name, 0, MAX_PATH_LEN);
    memset((char*) & best_candidate.section, 0, MAX_PATH_LEN);
    for (const auto& section : proc_mapping){
        set<struct symbol> section_symbols = section.second;
        set<struct symbol>::iterator it = section_symbols.lower_bound(address_container);
        if (it != section_symbols.end()){
            if (it->address == address){
                // if we found a match just break and move on.
                memcpy(&best_candidate, &*it, sizeof(struct symbol));
                break;
            }
            //check that there exists a lower value
            if (it != section_symbols.begin()){
                // get that lower value
                it--;
                // make comparison
                if (it->address > best_candidate.address){
                    //copy it
                    memcpy(&best_candidate, &*it, sizeof(struct symbol));
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
    //printf("in dt_hash_section %s %llx\n", name.c_str(), (long long unsigned int) dt_hash);
    struct dt_hash_section dt;
    if (panda_virtual_memory_read(cpu, dt_hash, (uint8_t*) &dt, sizeof(struct dt_hash_section))!= MEMTX_OK){
        //printf("got error 2\n");
        return -1;
        //goto nextloop;
    }
    //printf("strtab %llx\n", (long long unsigned int)strtab);
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
    uint32_t* buckets = (uint32_t*) malloc(ght.nbuckets*sizeof(uint32_t));

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
        if (find(begin(possible_tags), end(possible_tags), (int)tag.d_tag) != end(possible_tags)){
            uint32_t candidate = tag.d_un.d_ptr;
            if (candidate > symtab && candidate < symtab_min){
                symtab_min = candidate;
            }
        }
    }
    return (symtab_min - symtab)/(sizeof(ELF(Dyn)));
}


void find_symbols(CPUState* cpu, OsiProc *current, OsiModule *m){
    target_ulong asid = panda_current_asid(cpu);
    auto proc_mapping = symbols[asid];
    if (m->name == NULL){
        //printf("%s name is null\n", current->name);
        return;
    }
    string name(m->name);
    // we already read this one
    if (proc_mapping.find(name) != proc_mapping.end()){
        //printf("%s %s already exists \n", current->name, m->name);
        return;
    }
    // static variable to store first 4 bytes of mapping
    char elfhdr[4];

    // read first 4 bytes
    if (likely(panda_virtual_memory_read(cpu, m->base, (uint8_t*)elfhdr, 4) != MEMTX_OK)){
        // can't read page.
        return;
    }
    // is it an ELF header?
    if (unlikely(elfhdr[0] == '\x7f' && elfhdr[1] == 'E' && elfhdr[2] == 'L' && elfhdr[3] == 'F')){
        //printf("looking at section %s:%s %llx\n", current->name, m->name, (long long unsigned int) m->base);
        //printf("%s %s elf header %llx\n", current->name, m->name, (long long unsigned int) m->base);
        // allocate buffer for start of ELF. read first page
        //char* buff = (char*)malloc(0x1000);
        ELF(Ehdr) ehdr;
        // attempt to read memory allocation
        if (panda_virtual_memory_read(cpu, m->base, (uint8_t*)&ehdr, sizeof(ELF(Ehdr))) != MEMTX_OK){
            //printf("cant read elf header\n");
            // can't read it; free buffer and move on.
            //free(buff);
            return;
            //return;
        }
        target_ulong phnum = ehdr.e_phnum;
        target_ulong phoff = ehdr.e_phoff;

        ELF(Phdr) dynamic_phdr;
        for (int j=0; j<phnum; j++){
            if (panda_virtual_memory_read(cpu, m->base + phoff + (j*sizeof(ELF(Phdr))), (uint8_t*)&dynamic_phdr, sizeof(ELF(Phdr))) != MEMTX_OK){
                return;
            }
            if (dynamic_phdr.p_type == PT_DYNAMIC){
                break;
            }else if (dynamic_phdr.p_type == PT_NULL){
                //printf("hit PT_NULL\n");
                return;
            }else if (j == phnum -1){
                //printf("hit phnum-1\n");
                return;
            }
        }
        int numelements_dyn = dynamic_phdr.p_filesz / sizeof(ELF(Dyn));
        // iterate over dynamic program headers and find strtab
        // and symtab
        ELF(Dyn) tag;
        target_ulong strtab = 0, symtab = 0, strtab_size = 0, dt_hash = 0, gnu_hash = 0;
        int j = 0;
        while (j < numelements_dyn){
            if (panda_virtual_memory_read(cpu, m->base + dynamic_phdr.p_vaddr + (j*sizeof(ELF(Dyn))), (uint8_t*)&tag, sizeof(ELF(Dyn))) != MEMTX_OK){
                //printf("%s:%s Failed to read entry %d\n", name.c_str(), current->name, j);
                return;
            }
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
               // printf("DT_HASH_ORIGINAL 0x%llx\n", (long long unsigned int) gnu_hash);
            }else if (tag.d_tag == DT_NULL){
                //printf("Found DT_NULL \n");
                j = numelements_dyn;
                //break;
            }
            j++;
        }  
        
        if (dt_hash == 0 && gnu_hash == 0){
            //printf("%s strtab %llx symtab %llx dt_hash %llx\n",name.c_str(), (long long unsigned int)strtab, (long long unsigned int)symtab, (long long unsigned int)dt_hash);
            //printf("%s %s  got error 1\n", current->name, m->name);
            return;
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
            //printf("numelements_symtab not working\n");
            return;
        }

        target_ulong symtab_size = numelements_symtab * sizeof(ELF(Sym));
       // printf("numelements_symtab %x\n", numelements_symtab);

        //printf("symtab_size %llx strtab_size %llx\n",(long long unsigned int)symtab_size, (long long unsigned int)strtab_size);

        char* symtab_buf = (char*)malloc(symtab_size);
        char* strtab_buf = (char*)malloc(strtab_size);

        //printf("symtab %llx\n", (long long unsigned int) symtab);
        //printf("symtab: 0x%llx  0x%llx\n", symtab, strtab);
        set<struct symbol> symbols_list_internal;
        if (panda_virtual_memory_read(cpu, symtab, (uint8_t*)symtab_buf, symtab_size) == MEMTX_OK && panda_virtual_memory_read(cpu, strtab, (uint8_t*) strtab_buf, strtab_size) == MEMTX_OK){
            int i = 0; 
            for (;i<numelements_symtab; i++){
                ELF(Sym)* a = (ELF(Sym)*) (symtab_buf + i*sizeof(ELF(Sym)));
                if (a->st_name < strtab_size && a->st_value != 0){
                    struct symbol s;
                    strncpy((char*)&s.name, &strtab_buf[a->st_name], MAX_PATH_LEN-1);
                    strncpy((char*)&s.section, m->name, MAX_PATH_LEN-1);
                    s.address = m->base + a->st_value;
                    //printf("found symbol %s %s 0x%llx\n",s.section, &strtab_buf[a->st_name],(long long unsigned int)s.address);
                    symbols_list_internal.insert(s);
                    check_symbol_for_hook(cpu, s, m);
                    //printf("%s %s %llx\n", m->name, s.name, (long long unsigned int)s.address+ a->st_name);
                }
            }
            proc_mapping[name] = symbols_list_internal;
            symbols[asid] = proc_mapping;
        }else{
            //printf("couldn't read symtab_buf %llx %llx %llx\n", (long long unsigned int)symtab, (long long unsigned int) m->base, (long long unsigned int)symtab_size);
        }
        free(symtab_buf);
        free(strtab_buf);
    }
}


void update_symbols_in_space(CPUState* cpu){
    if (panda_in_kernel(cpu)){
        return;
    }
    OsiProc *current = get_current_process(cpu);
    GArray *ms = get_mappings(cpu, current);

    
    if (ms == NULL) {
        return;
    } else {
        //iterate over mappings
        for (int i = 0; i < ms->len; i++) {
            OsiModule *m = &g_array_index(ms, OsiModule, i);
            find_symbols(cpu, current, m);
        }
    }
}

void* self_ptr;
panda_cb pcb_asid;
panda_cb pcb_bbe;
panda_cb pcb_bbe_execve;


void bbe(CPUState *env, TranslationBlock *tb){
    if (!panda_in_kernel(env)){
        update_symbols_in_space(env);
        panda_disable_callback(self_ptr, PANDA_CB_BEFORE_BLOCK_EXEC, pcb_bbe);
    }
}

bool asid_changed(CPUState *env, target_ulong old_asid, target_ulong new_asid) {
    //printf("asid changed\n");
    panda_enable_callback(self_ptr, PANDA_CB_BEFORE_BLOCK_EXEC, pcb_bbe);
    return false;
}

void hook_program_start(CPUState *env, TranslationBlock* tb, struct hook* h){
    //printf("got to program start 0x%llx\n", (long long unsigned int)rr_get_guest_instr_count());
    update_symbols_in_space(env);
    h->enabled = false;
}

bool first_require = false;

void bbe_execve(CPUState *env, TranslationBlock *tb){
    if (unlikely(!panda_in_kernel(env))){
        target_ulong sp = panda_current_sp(env);
        target_ulong argc;
        if (panda_virtual_memory_read(env, sp, (uint8_t*) &argc, sizeof(argc))== MEMTX_OK){
            // we read argc, but just to check the stack is readable.
            // don't use it. just iterate and check for nulls.
            int ptrlistpos = 1;
            // these are arguments to the binary. we don't read
            // them but you could.
            target_ulong ptr;
            while (true){
                if (panda_virtual_memory_read(env, sp+(ptrlistpos*sizeof(target_ulong)), (uint8_t*) &ptr, sizeof(ptr)) != MEMTX_OK){
                    panda_disable_callback(self_ptr, PANDA_CB_BEFORE_BLOCK_EXEC, pcb_bbe_execve);
                    return;
                }
                ptrlistpos++;
                if (ptr == 0){
                    break;
                }
            }
            // these are environmental variables. we don't read
            // them, but you could.
            while (true){
                if (panda_virtual_memory_read(env, sp+(ptrlistpos*sizeof(target_ulong)), (uint8_t*) &ptr, sizeof(ptr)) != MEMTX_OK){
                    panda_disable_callback(self_ptr, PANDA_CB_BEFORE_BLOCK_EXEC, pcb_bbe_execve);
                    return;
                }
                ptrlistpos++;
                if (ptr == 0){
                    break;
                }
            }
            target_ulong entrynum, entryval;
            while (true){
                if (panda_virtual_memory_read(env, sp+(ptrlistpos*sizeof(target_ulong)), (uint8_t*) &entrynum, sizeof(entrynum)) != MEMTX_OK || panda_virtual_memory_read(env, sp+((ptrlistpos+1)*sizeof(target_ulong)), (uint8_t*) &entryval, sizeof(entryval))){
                    panda_disable_callback(self_ptr, PANDA_CB_BEFORE_BLOCK_EXEC, pcb_bbe_execve);
                    return;
                }
                ptrlistpos+=2;
                if (entrynum == AT_NULL){
                    break;
                }else if (entrynum == AT_ENTRY){
                    if (!first_require){
                        panda_require("hooks");
                        first_require = true;
                    }
                    struct hook h;
                    h.start_addr = entryval;
                    h.end_addr = entryval;
                    h.asid = panda_current_asid(env);
                    h.type = PANDA_CB_BEFORE_BLOCK_EXEC;
                    h.cb.before_block_exec = hook_program_start;
                    h.km = MODE_USER_ONLY;
                    h.enabled = true;

                    void* hooks = panda_get_plugin_by_name("hooks");
                    if (hooks != NULL){
                        void (*dlsym_add_hook)(struct hook*) = (void(*)(struct hook*)) dlsym(hooks, "add_hook");
                        if ((void*)dlsym_add_hook != NULL) {
                            dlsym_add_hook(&h);
                        }
                    }

                }
            }

        }
        panda_disable_callback(self_ptr, PANDA_CB_BEFORE_BLOCK_EXEC, pcb_bbe_execve);
    }
}

void execve_cb(CPUState *cpu, target_ptr_t pc, target_ptr_t filename, target_ptr_t argv, target_ptr_t envp) {
    panda_enable_callback(self_ptr, PANDA_CB_BEFORE_BLOCK_EXEC, pcb_bbe_execve);
}

void execveat_cb (CPUState* cpu, target_ptr_t pc, int dfd, target_ptr_t filename, target_ptr_t argv, target_ptr_t envp, int flags) {
    panda_enable_callback(self_ptr, PANDA_CB_BEFORE_BLOCK_EXEC, pcb_bbe_execve);
}


bool init_plugin(void *self) {
    self_ptr = self;
    panda_enable_precise_pc();
    panda_disable_tb_chaining();
    pcb_asid.asid_changed = asid_changed;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb_asid);
    pcb_bbe.before_block_exec = bbe;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb_bbe);
    pcb_bbe_execve.before_block_exec = bbe_execve;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb_bbe_execve);
    panda_disable_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb_bbe_execve);
    panda_require("osi");
    assert(init_osi_api());
    
    #if defined(TARGET_PPC)
        fprintf(stderr, "[ERROR] asidstory: PPC architecture not supported by syscalls2!\n");
        return false;
    #else
        panda_require("syscalls2");
        assert(init_syscalls2_api());
        PPP_REG_CB("syscalls2", on_sys_execve_enter, execve_cb);
        PPP_REG_CB("syscalls2", on_sys_execveat_enter, execveat_cb);
    #endif
    return true;
}

void uninit_plugin(void *self) { }
