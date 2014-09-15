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

/*
 * This is the start of instrumentation code that we can run as we process
 * taint.  To start with, this implements the gathering of taint statistics for
 * the guest memory as we process taint.
 */

#include <stdint.h>
#include <stdio.h>

extern "C" {
#include "qemu-common.h"
#include "cpu-all.h"
}

// Compiler hack, these will get redefined
#undef TRUE
#undef FALSE

#include "bitvector_label_set.cpp"
#include "panda_stats.h"

#define INSTR_INTERVAL 10000

FILE *taintstats;
uint64_t instr_count = 0;

// Prints out tainted memory
void memplot(Shad *shad){
    FILE *memplotlog = fopen("memory.csv", "w");
    fprintf(memplotlog, "\"Address\",\"Label\",\"Type\"\n");
    /*
    unsigned int i;
    for (i = 0; i < 0xffffffff; i++){
#ifdef TARGET_X86_64
        LabelSet *ls = shad_dir_find_64(shad->ram, i);
        if (ls){
            unsigned int j;
            for (j = 0; j < ls->set.current_size; j++){
                fprintf(memplotlog, "%d,%d,%d\n", i, ls->set->members[j],
                    ls->type);
            }
        }
#else
        if (get_ram_bit(shad, i)){
            LabelSet *ls = shad_dir_find_32(shad->ram, i);
            unsigned int j;
            for (j = 0; j < ls->set->current_size; j++){
                fprintf(memplotlog, "%d,%d,%d\n", i, ls->set->members[j],
                    ls->type);
            }
        }
#endif
    }
    */
    fclose(memplotlog);
}

struct labelset_print_info {
    FILE* bufplotlog;
    const char* prefix;
    LabelSetType type;
    uint64_t addr;
};

static int panda_stats_print_labelset(uint32_t label_no, void* opaque){
    labelset_print_info *print_info = reinterpret_cast<labelset_print_info*>(opaque);
    ::fprintf(print_info->bufplotlog, "%s%lu,%u,%d\n", print_info->prefix, 
              print_info->addr, label_no, print_info->type);
    return 0;
}

void panda_stats_bufplot(FILE* bufplotlog,
                         const char* prefix,
                         LabelSet& ls,
                         uint64_t i){
    labelset_print_info info;
    info.bufplotlog = bufplotlog;
    info.prefix = prefix;
    info.type = ls.type;
    info.addr = i;
    bitset_iter(ls.set, panda_stats_print_labelset, &info);
}


// Prints out taint of memory buffer
// FIXME TODO: fix this broken thing, merge in Tim's taint callback stuff, an
// improved version of this will be a taint plugin 'query' callback
void bufplot(CPUState *env, Shad *shad, Addr *addr, int length){
    FILE *bufplotlog = fopen("taint_query.csv", "a+");
    fprintf(bufplotlog, "\"Address\",\"Label\",\"Type\"\n");
    uint64_t i;
    LabelSet *ls;

    if (addr->typ == IADDR){
        for (i = addr->val.ia; i < addr->val.ia+length; i++){
            ls = shad_dir_find_64(shad->io, i);
            if (ls){
                panda_stats_bufplot(bufplotlog, "IO ", *ls, i);
            }
        }
    }

    else if (addr->typ == MADDR){
        for (i = addr->val.ma; i < addr->val.ma+length; i++){
#ifdef TARGET_X86_64

#ifdef CONFIG_SOFTMMU
            ls = shad_dir_find_64(shad->ram, cpu_get_phys_addr(env, i));
#else // CONFIG_SOFTMMU
            LabelSet *ls = shad_dir_find_64(shad->ram, i);
#endif // CONFIG_SOFTMMU
            if (ls){
                panda_stats_bufplot(bufplotlog, "RAM ", *ls, i);
            }
#else // TARGET_X86_64

#ifdef CONFIG_SOFTMMU
            if (get_ram_bit(shad, cpu_get_phys_addr(env, i))){
                ls = shad_dir_find_32(shad->ram, cpu_get_phys_addr(env, i));
#else // CONFIG_SOFTMMU
            if (get_ram_bit(shad, i)){
                LabelSet *ls = shad_dir_find_32(shad->ram, i);
#endif // CONFIG_SOFTMMU
                panda_stats_bufplot(bufplotlog, "", *ls, i);
            }
#endif // TARGET_X86_64
        }
    }

    else {
        // Other address types not supported
        assert(0);
    }
    fclose(bufplotlog);
}

/*
 * Dump the number of tainted bytes of guest memory to a file on an instruction
 * interval defined by INSTR_INTERVAL.
 */
void dump_taint_stats(Shad *shad){
    assert(shad != NULL);
    uint64_t tainted_addrs = 0;
    instr_count++;
    if (__builtin_expect(((instr_count % INSTR_INTERVAL) == 0), 0)){
        if (__builtin_expect((taintstats == NULL), 0)){
            taintstats = fopen("taintstats.csv", "w");
            fprintf(taintstats, "\"Instrs\",\"TaintedAddrs\"\n");
        }
#ifdef TARGET_X86_64
        tainted_addrs = shad_dir_occ_64(shad->ram);
#else
        tainted_addrs = shad_dir_occ_32(shad->ram);
#endif
        fprintf(taintstats, "%lu,%lu\n", instr_count, tainted_addrs);
        fflush(taintstats);
    }
}

void cleanup_taint_stats(void){
    if (taintstats){
        fclose(taintstats);
    }
}
