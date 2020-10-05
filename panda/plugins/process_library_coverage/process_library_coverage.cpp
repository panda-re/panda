/* PANDABEGINCOMMENT
 * 
 * Authors:
 * Luke Craig
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#include <linux/elf.h>
#include <iostream> 
#include <iterator> 
#include <map> 

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}
using namespace std;

map<target_ulong, map<std::string, target_ulong>> mapping;

#ifdef TARGET_ABI_BITS == 32
#define ELF_ Elf32
#else
#define ELF_ Elf64
#endif


void update_symbols_in_space(CPUState* cpu){
    map<std::string, target_ulong> symbol_to_address;
    OsiProc *current = get_current_process(cpu);
    GArray *ms = get_mappings(cpu, current);
    
    char elfhdr[4];
    if (ms == NULL) {
        return;
    } else {
        for (int i = 0; i < ms->len; i++) {
            OsiModule *m = &g_array_index(ms, OsiModule, i);
            panda_virtual_memory_read(cpu, m->base, elfhdr, 4);
            target_ulong phnum, phoff;
            if (elfhdr[0] == '\x7f' && elfhdr[1] == 'E' && elfhdr[2] == 'L' && elfhdr[3] == 'F'){
                char* buff = malloc(m->size)
                panda_virtual_memory_read(cpu, m->base, buff, m->size);
                ELF_Ehdr *ehdr = (ELF_Ehdr*) buff;
                target_ulong phnum = ehdr->e_phnum;
                target_ulong phoff = ehdr->e_phoff;
                ELF_Phdr* dynamic_phdr = NULL;
                for (int j=0; j<phnum; j++){
                    dynamic_phdr = (ELF_Phdr*)(buff + (j* phoff));
                    if (phdr->p_type == PT_DYNAMIC){
                        break;
                    }else if (phdr->p_type == PT_NULL){
                        return;
                    }
                }
                char* dynamic_section = malloc(dynamic_phdr->p_filesz);



            }
        }
    }
    
    target_ulong asid = panda_current_asid(cpu);
}



bool init_plugin(void *self) {
    panda_require("osi");
    assert(init_osi_api());
    panda_require("syscalls2");
    assert(init_syscalls2_api());
    return true;
}

void uninit_plugin(void *self) { }
