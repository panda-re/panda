/*!
 * @file taint2_hypercalls.cpp
 * @brief Support for hypercalls from the PANDA guest to the taint2 plugin.
 *
 * @author
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * @copyright This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 */
#ifdef TAINT2_HYPERCALLS

#include <cstdio>
#include <vector>
#include "taint2_hypercalls.h"
#include "taint_api.h"
extern "C" {
#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"
}

#ifdef TARGET_I386
// shorcuts for accesing the values of x86 registers
#define EAX ((CPUArchState*)cpu->env_ptr)->regs[R_EAX]
#define EBX ((CPUArchState*)cpu->env_ptr)->regs[R_EBX]
#define ECX ((CPUArchState*)cpu->env_ptr)->regs[R_ECX]
#define EDI ((CPUArchState*)cpu->env_ptr)->regs[R_EDI]
#endif

// max length of strnlen or taint query
#define QUERY_HYPERCALL_MAX_LEN 32

extern bool taintEnabled;

/**
 * @brief Constructs a pandalog message for src-level info.
 */
Panda__SrcInfo *pandalog_src_info_create(PandaHypercallStruct phs) {
    Panda__SrcInfo *si = (Panda__SrcInfo *)malloc(sizeof(Panda__SrcInfo));
    *si = PANDA__SRC_INFO__INIT;
    si->filename = phs.src_filename;
    si->astnodename = phs.src_ast_node_name;
    si->linenum = phs.src_linenum;
    si->has_insertionpoint = 0;
    if (phs.insertion_point) {
        si->has_insertionpoint = 1;
        si->insertionpoint = phs.insertion_point;
    }
    si->has_ast_loc_id = 1;
    si->ast_loc_id = phs.src_filename;
    return si;
}

/**
 * @brief Hypercall-initiated taint query of some src-level extent.
 */
void taint_query_hypercall(PandaHypercallStruct phs) {
    CPUState *cpu = first_cpu;
    if  (pandalog && taintEnabled && (taint2_num_labels_applied() > 0)) {
        // okay, taint is on and some labels have actually been applied
        // is there *any* taint on this extent
        uint32_t num_tainted = 0;
        bool is_strnlen = ((int) phs.len == -1);
        uint32_t offset=0;
        while (true) {
            uint32_t va = phs.buf + offset;
            uint32_t pa =  panda_virt_to_phys(cpu, va);
            if (is_strnlen) {
                uint8_t c;
                panda_virtual_memory_rw(cpu, pa, &c, 1, false);
                // null terminator
                if (c==0) break;
            }
            if ((int) pa != -1) {
                Addr a = make_maddr(pa);
                if (taint2_query(a)) {
                    num_tainted ++;
                }
            }
            offset ++;
            // end of query by length or max string length
            if (!is_strnlen && offset == phs.len) break;
            if (is_strnlen && (offset == QUERY_HYPERCALL_MAX_LEN)) break;
        }
        uint32_t len = offset;
        if (num_tainted) {
            // ok at least one byte in the extent is tainted
            // 1. write the pandalog entry that tells us something was tainted on this extent
            Panda__TaintQueryHypercall *tqh = (Panda__TaintQueryHypercall *) malloc (sizeof (Panda__TaintQueryHypercall));
            *tqh = PANDA__TAINT_QUERY_HYPERCALL__INIT;
            tqh->buf = phs.buf;
            tqh->len = len;
            tqh->num_tainted = num_tainted;
            // obtain the actual data out of memory
            // NOTE: first X bytes only!
            uint32_t data[QUERY_HYPERCALL_MAX_LEN];
            uint32_t n = len;
            // grab at most X bytes from memory to pandalog
            // this is just a snippet.  we dont want to write 1M buffer
            if (QUERY_HYPERCALL_MAX_LEN < len) n = QUERY_HYPERCALL_MAX_LEN;
            for (uint32_t i=0; i<n; i++) {
                data[i] = 0;
                uint8_t c;
                panda_virtual_memory_rw(cpu, phs.buf+i, &c, 1, false);
                data[i] = c;
            }
            tqh->n_data = n;
            tqh->data = data;
            // 2. write out src-level info
            Panda__SrcInfo *si = pandalog_src_info_create(phs);
            tqh->src_info = si;
            // 3. write out callstack info
            Panda__CallStack *cs = pandalog_callstack_create();
            tqh->call_stack = cs;
            std::vector<Panda__TaintQuery *> tq;
            for (uint32_t offset=0; offset<len; offset++) {
                uint32_t va = phs.buf + offset;
                uint32_t pa =  panda_virt_to_phys(cpu, va);
                if ((int) pa != -1) {
                    Addr a = make_maddr(pa);
                    if (taint2_query(a)) {
                        tq.push_back(taint2_query_pandalog(a, offset));
                    }
                }
            }
            tqh->n_taint_query = tq.size();
            tqh->taint_query = (Panda__TaintQuery **) malloc(sizeof(Panda__TaintQuery *) * tqh->n_taint_query);
            for (uint32_t i=0; i<tqh->n_taint_query; i++) {
                tqh->taint_query[i] = tq[i];
            }
            Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
            ple.taint_query_hypercall = tqh;
            pandalog_write_entry(&ple);
            free(tqh->src_info);
            pandalog_callstack_free(tqh->call_stack);
            for (uint32_t i=0; i<tqh->n_taint_query; i++) {
                pandalog_taint_query_free(tqh->taint_query[i]);
            }
            free(tqh);
        }
    }
}

void lava_attack_point(PandaHypercallStruct phs) {
    if (pandalog) {
        Panda__AttackPoint *ap = (Panda__AttackPoint *)malloc(sizeof (Panda__AttackPoint));
        *ap = PANDA__ATTACK_POINT__INIT;
        ap->info = phs.info;
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        ple.attack_point = ap;
        ple.attack_point->src_info = pandalog_src_info_create(phs);
        ple.attack_point->call_stack = pandalog_callstack_create();
        pandalog_write_entry(&ple);
        free(ple.attack_point->src_info);
        pandalog_callstack_free(ple.attack_point->call_stack);
        free(ap);
    }
}

int guest_hypercall_callback(CPUState *cpu) {
#if defined(TARGET_I386)
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    if (taintEnabled) {
        if (EAX == 7 || EAX == 8) {
            target_ulong buf_start = EBX;
            target_ulong buf_len = ECX;
            long label = EDI;
            if (R_EAX == 7) {
                // Standard buffer label
                printf("taint2: single taint label\n");
                taint2_add_taint_ram_single_label(cpu, (uint64_t)buf_start,
                                                  (int)buf_len, label);
            }
            else if (R_EAX == 8) {
                // Positional buffer label
                printf("taint2: positional taint label\n");
                taint2_add_taint_ram_pos(cpu, (uint64_t)buf_start, (int)buf_len, label);
            }
        }
        else {
            // LAVA Hypercall
            target_ulong addr = panda_virt_to_phys(cpu, env->regs[R_EAX]);
            if ((int)addr == -1) {
                // if EAX is not a valid ptr, then it is unlikely that this is a
                // PandaHypercall which requires EAX to point to a block of memory
                // defined by PandaHypercallStruct
                printf ("cpuid with invalid ptr in EAX: vaddr=0x%x paddr=0x%x. Probably not a Panda Hypercall\n",
                        (uint32_t) env->regs[R_EAX], (uint32_t) addr);
            }
            else if (pandalog) {
                PandaHypercallStruct phs;
                panda_virtual_memory_rw(cpu, env->regs[R_EAX], (uint8_t *) &phs, sizeof(phs), false);
                if (phs.magic == 0xabcd) {
                    if  (phs.action == 11) {
                        // it's a lava query
                        taint_query_hypercall(phs);
                    }
                    else if (phs.action == 12) {
                        // it's an attack point sighting
                        lava_attack_point(phs);
                    }
                    else if (phs.action == 13) {
                        // it's a pri taint query point
                        // do nothing and let pri_taint with hypercall
                        // option handle it
                    }
                    else if (phs.action == 14) {
                        // reserved for taint-exploitability
                    }
                    else {
                        printf("Unknown hypercall action %d\n", phs.action);
                    }
                }
                else {
                    printf ("Invalid magic value in PHS struct: %x != 0xabcd.\n", phs.magic);
                }
            }
        }
    }
    return 1;
#else
    // other architectures
    return 0;
#endif
}
#endif // TAINT2_HYPERCALLS
