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


// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}
using namespace std;

map<target_ulong, map<std::string, target_ulong>> mapping;

#if TARGET_ABI_BITS == 32
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
                if (panda_virtual_memory_read(cpu, m->base, buff, m->size) != MEMTX_OK){
                    free(buff);
                    continue;
                }
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
                if(panda_virtual_memory_read(cpu, m->base + dynamic->p_vaddr, dynamic->p_filesize) != MEMTX_OK){
                    free(dynamic_section);
                    free(buff);
                    continue;
                }
                int numelements = dynamic_phdr->p_filesz / sizeof(ELF_Ehdr);
                
                target_ulong strtab = NULL, symtab = NULL;
                for (int j=0; j<numelements; j++){
                   ELF_Dyn *tag = (ELF_Dyn *)(dynamic + j*sizeof(ELF_Dyn));
                   if (tag->d_tag == DT_STRTAB){
                       strtab = tag->d_un->d_ptr;
                   }else if (tag->d_tab == DT_SYMTAB){
                       symtab = tag->d_un->d_ptr;
                   }
                }

                if (strtab == NULL || symtab == NULL){
                    free(dynamic_section)
                    free(buff);
                    continue;
                }

                target_ulong strtab_min = strtab + 0x100000;
                target_ulong symtab_min = symtab + 0x100000;
                uint32_t possible_tags[] = [DT_PLTGOT, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_INIT, 
                                            DT_FINI, DT_REL, DT_DEBUG, DT_JMPREL, DT_INIT_ARRAY, DT_FINI_ARRAY,
                                            DT_PREINIT_ARRAY, DT_SUNW_RTLDINF, DT_CONFIG, DT_DEPAUDIT, DT_AUDIT,
                                            DT_PLTPAD, DT_MOVETAB, DT_SYMINFO, DT_VERDEF, DT_VERNEED]
                for (int j=0; j<numelements; j++){
                   ELF_Dyn *tag = (ELF_Dyn *)(dynamic + j*sizeof(ELF_Dyn));
                   if (find(begin(possible_tags), end(possible_tags), tag->d_tag) != end(possible_tags)){
                       uint32_t candidate = tag->d_un->d_ptr;
                       if (candidate > strtab && candidate < strtab_min){
                           strtab_min = candidate;
                       }
                       if (candidate > symtab && candidate < symtab_min){
                           symtab_min = candidate;
                       }
                   }
                }

                target_ulong strtab_size = strtab_min - strtab;
                target_ulong symtab_size = symtab_min - symtab;

                



            }
        }
    }
    
    target_ulong asid = panda_current_asid(cpu);
}

string read_str(CPUState* cpu, target_ulong ptr){
    string buf = "";
    char tmp;
    while (true){
        panda_virtual_memory_read(cpu, ptr+i, &tmp,1);
        buf += tmp;
        if (tmp == 0){
            break;
        }
    }
    return buf;
}



vector<string> program_started_list;

void bbe(CPUState *env, TranslationBlock *tb) {
    if (!panda_in_kernel(env)){
        OsiProc *current = get_current_process();
        if (!current || !current->name){
            return;
        }
        size_t s_len = strlen(current->name);
        vector<string>::const_iterator it = program_started_list.cbegin();
        while (it !=  program_started_list.cend()) {
            string it_val = *it;
            size_t it_len = it_val.length();
            if (it_val.find(current->name) != string::npos){
                update_symbols_in_space(env);
                program_started_list.erase(it);
                break;
            }
        }
    }
}

void on_sys_execve_enter(CPUState *cpu, target_ulong pc, target_ulong filename, target_ulong argv, target_ulong envp){
    string progname = read_str(cpu, filename);
    program_started_list.insert(progname);
}

void on_sys_execveat_enter(CPUState *cpu, target_ulong pc, int32_t dfd, target_ulong filename, target_ulong argv, target_ulong envp, int32_t flags){
    string progname = read_str(cpu, filename);
    program_started_list.insert(progname);
}





bool init_plugin(void *self) {
    panda_cb pcb;
    pcb.before_block_exec = bbe;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    panda_require("osi");
    assert(init_osi_api());
    panda_require("syscalls2");
    assert(init_syscalls2_api());
    PPP_REG_CB("syscalls2", on_sys_execve_enter, on_sys_execve_enter);
    PPP_REG_CB("syscalls2", on_sys_execveat_enter, on_sys_execveat_enter);
    return true;
}

void uninit_plugin(void *self) { }
