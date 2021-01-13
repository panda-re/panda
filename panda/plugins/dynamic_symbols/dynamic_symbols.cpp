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
#include <iostream> 
#include <vector>
#include <string>
#include <iterator> 
#include <map> 
#include <algorithm>
#include "panda/plugin.h"
#include "osi/osi_types.h"
#include "osi/osi_ext.h"
#include "syscalls2/syscalls_ext_typedefs.h"
#include "syscalls2/syscalls2_info.h"
#include "syscalls2/syscalls2_ext.h"
#include <unordered_map>


// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
#include "dynamic_symbols_int_fns.h"

}
using namespace std;

map<target_ulong, map<std::string, target_ulong>> mapping;

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

std::vector<int> possible_tags{ DT_PLTGOT , DT_HASH , DT_STRTAB , DT_SYMTAB , DT_RELA , DT_INIT , DT_FINI , DT_REL , DT_DEBUG , DT_JMPREL, 25, 26, 32, DT_SUNW_RTLDINF , DT_CONFIG , DT_DEPAUDIT , DT_AUDIT , DT_PLTPAD , DT_MOVETAB , DT_SYMINFO , DT_VERDEF , DT_VERNEED };

unordered_map<target_ulong, unordered_map<string, vector<struct symbol>>> symbols;

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
                    printf("result: %s %s\n", section.first.c_str(), val.name);
                    strncpy((char*) &val.section, section.first.c_str(), MAX_PATH_LEN);
                    return val;
                }
            }
        } 
    }
    struct symbol blank;
    blank.address = 0;
    char none[] = "NULL";
    strncpy((char*) & blank.name, none, strlen(none)+1);
    strncpy((char*) & blank.section, none, strlen(none)+1);
    return blank;
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

void update_symbols_in_space(CPUState* cpu){
    if (panda_in_kernel(cpu)){
        return;
    }
    OsiProc *current = get_current_process(cpu);
    GArray *ms = get_mappings(cpu, current);
    target_ulong asid = panda_current_asid(cpu);

    auto proc_mapping = symbols[asid];

    
    // static variable to store first 4 bytes of mapping
    char elfhdr[4];
    if (ms == NULL) {
        return;
    } else {
        //iterate over mappings
        for (int i = 0; i < ms->len; i++) {
            OsiModule *m = &g_array_index(ms, OsiModule, i);
            if (m->name == NULL){
                //printf("name is null\n");
                continue;
            }
            std::string name(m->name);
            // we already read this one
            if (proc_mapping.find(name) != proc_mapping.end()){
                //printf("%s already exists \n", m->name);
                continue;
            }

            // read first 4 bytes
            if (panda_virtual_memory_read(cpu, m->base, (uint8_t*)elfhdr, 4) != MEMTX_OK){
                // can't read page.
                continue;
            }
            // is it an ELF header?
            if (elfhdr[0] == '\x7f' && elfhdr[1] == 'E' && elfhdr[2] == 'L' && elfhdr[3] == 'F'){
                //printf("%s elf header %llx\n", m->name, (long long unsigned int) m->base);
                // allocate buffer for start of ELF. read first page
                char* buff = (char*)malloc(0x1000);
                // attempt to read memory allocation
                if (panda_virtual_memory_read(cpu, m->base, (uint8_t*)buff, 0x1000) != MEMTX_OK){
                    //printf("cant read elf header\n");
                    // can't read it; free buffer and move on.
                    free(buff);
                    continue;
                }
                ELF(Ehdr) *ehdr = (ELF(Ehdr)*) buff;
                target_ulong phnum = ehdr->e_phnum;
                target_ulong phoff = ehdr->e_phoff;
                //printf("phnum %x phoff %x\n", (int)phnum, (int)phoff);
                ELF(Phdr)* dynamic_phdr = NULL;
                for (int j=0; j<phnum; j++){
                    dynamic_phdr = (ELF(Phdr)*)(buff + phoff + (j* sizeof(ELF(Phdr))));
                    if (dynamic_phdr->p_type == PT_DYNAMIC){
                        break;
                    }else if (dynamic_phdr->p_type == PT_NULL){
                        return;
                    }else if (j== phnum -1){
                        return;
                    }
                }
                //printf("PT_DYNAMIC %llx\n", (long long unsigned int)dynamic_phdr->p_vaddr);
                char* dynamic_section = (char*)malloc(dynamic_phdr->p_filesz);
                // try to read dynamic section
                if(panda_virtual_memory_read(cpu, m->base + dynamic_phdr->p_vaddr, (uint8_t*) dynamic_section, dynamic_phdr->p_filesz) != MEMTX_OK){
                    // failed to read dynamic section
                    //printf("failed to read dynamic section %s\n", m->name);
                    free(dynamic_section);
                    free(buff);
                    continue;
                }
                //printf("p_filesz: %llu\n", (long long unsigned int) dynamic_phdr->p_filesz);
                //printf("Ehdr size: %d\n", (int)sizeof(ELF(Dyn)));
                int numelements_dyn = dynamic_phdr->p_filesz / sizeof(ELF(Dyn));
                //assert(false);
                //printf("numelements_dyn: %d\n", numelements_dyn);
                
                // iterate over dynamic program headers and find strtab
                // and symtab
                target_ulong strtab = 0, symtab = 0, strtab_size = 0;
                for (int j=0; j<numelements_dyn; j++){
                    ELF(Dyn) *tag = (ELF(Dyn) *)(dynamic_section + j*sizeof(ELF(Dyn)));
                    if (tag->d_tag == DT_STRTAB){
                        //printf("Found DT_STRTAB\n");
                        strtab = tag->d_un.d_ptr;
                    }else if (tag->d_tag == DT_SYMTAB){
                        //printf("Found DT_SYMTAB\n");
                        symtab = tag->d_un.d_ptr;
                    }else if (tag->d_tag == DT_STRSZ ){
                        //printf("Found DT_STRSZ\n");
                        strtab_size = tag->d_un.d_ptr;
                    }
                }

                if (strtab == 0 || symtab == 0){
                    //printf("strtab or symtab missing %s\n", m->name);
                    free(dynamic_section);
                    free(buff);
                    continue;
                }

                // we don't actually have the size of these things 
                // (not included) so we find it by finding the next
                // closest section
                target_ulong strtab_min = strtab + 0x100000;
                target_ulong symtab_min = symtab + 0x100000;
                for (int j=0; j< numelements_dyn; j++){
                   ELF(Dyn) *tag = (ELF(Dyn) *)(dynamic_section + j*sizeof(ELF(Dyn)));
                    if (std::find(std::begin(possible_tags), std::end(possible_tags), (int)tag->d_tag) != std::end(possible_tags)){
                        uint32_t candidate = tag->d_un.d_ptr;
                        if (candidate > strtab && candidate < strtab_min){
                            strtab_min = candidate;
                        }
                        if (candidate > symtab && candidate < symtab_min){
                            symtab_min = candidate;
                        }
                    }
                }

                // take those and convert to sizes
                if (strtab_size == 0){
                    strtab_size = strtab_min - strtab;
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

                //printf("strtab: %llx symtab: %llx\n", (long long unsigned int) strtab, (long long unsigned int)symtab);

                // This first section maps strings to an index
                std::unordered_map<target_ulong, string> string_map;
                int index = 0;
                //printf("strtab %llx\n", (long long unsigned int)strtab);
                int numelements_symtab = 0;//symtab_size / sizeof(ELF(Sym));
                while (true){
                    string newstr = read_str(cpu, strtab + index);
                    //cout << "string " << numelements_symtab << " " << newstr << endl;
                    if (newstr.length() < 1) break;
                    string_map[index] = newstr;
                    numelements_symtab++;
                    index += newstr.length();
                    if (index > strtab_size) break;
                }
                target_ulong symtab_size = numelements_symtab * sizeof(ELF(Sym));
                //printf("numelements_symtab %x\n", numelements_symtab);
                char* symtab_buf = (char*)malloc(symtab_size);

                //printf("symtab %llx\n", (long long unsigned int) symtab);

                std::vector<struct symbol> symbols_list_internal;
                if (panda_virtual_memory_read(cpu, symtab, (uint8_t*)symtab_buf, symtab_size) == MEMTX_OK){
                    int i = 0; 
                    for (;i<numelements_symtab; i++){
                        ELF(Sym)* a = (ELF(Sym)*) (symtab_buf + i*sizeof(ELF(Sym)));
                        if (a->st_value != 0 && string_map.find(a->st_name)!=string_map.end()){
                            struct symbol s;
                            strncpy((char*)&s.name, string_map[a->st_name].c_str(), PATH_MAX);
                            s.address = m->base + a->st_value;
                            //printf("%llx %s %s %llx\n", (long long unsigned int) asid, m->name, s.name, (long long unsigned int)s.address);
                            symbols_list_internal.push_back(s);
                        }
                    }
                    proc_mapping[name] = symbols_list_internal;
                    symbols[asid] = proc_mapping;
                }else{
                    //printf("couldn't read symtab_buf %llx %llx %llx\n", (long long unsigned int)symtab, (long long unsigned int) m->base, (long long unsigned int)symtab_size);
                }
                free(dynamic_section);
                free(buff);
                free(symtab_buf);
            }else{
                // not an elf header. nothing to do.
            }
        }
    }
}

void* self_ptr;
panda_cb pcb;

void bbe(CPUState *env, TranslationBlock *tb){
    if (!panda_in_kernel(env)){
        //printf("Got out of kernel\n");
        update_symbols_in_space(env);
        panda_disable_callback(self_ptr, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    }
}

bool asid_changed(CPUState *env, target_ulong old_asid, target_ulong new_asid) {
    printf("Asid has changed. enabling bbe\n");
    if (panda_in_kernel(env)){
        panda_enable_callback(self_ptr, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    }
    return false;
}

bool init_plugin(void *self) {
    self_ptr = self;
    pcb.asid_changed = asid_changed;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);
    pcb.before_block_exec = bbe;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    panda_require("osi");
    assert(init_osi_api());
    return true;
}

void uninit_plugin(void *self) { }
