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
 * PANDA taint analysis plugin
 * Ryan Whelan, Tim Leek, Sam Coe, Nathan VanBenschoten
 */

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#ifdef NDEBUG
#undef NDEBUG
#endif

#include "label_set.h"


#include "../common/prog_point.h"

extern "C" {

#include <sys/time.h>

#include "qemu-common.h"
#include "cpu-all.h"
#include "panda_plugin.h"
#include "panda_plugin_plugin.h"
#include "panda_common.h"
#include "panda/network.h"
#include "rr_log.h"
#include "pandalog.h"
#include "cpu.h"
#include "panda/panda_addr.h"

#include "../callstack_instr/callstack_instr_ext.h"

extern int loglevel;

// For the C API to taint accessible from other plugins
void taint2_enable_taint(void);
int taint2_enabled(void);
void taint2_label_ram(uint64_t pa, uint32_t l) ;
void taint2_delete_ram(uint64_t pa);

   
uint8_t taint2_query_pandalog (Addr a);


uint32_t taint2_query(Addr a);
uint32_t taint2_query_ram(uint64_t pa);
uint32_t taint2_query_reg(int reg_num, int offset);
uint32_t taint2_query_llvm(int reg_num, int offset);


uint32_t taint2_query_tcn(Addr a);
uint32_t taint2_query_tcn_ram(uint64_t pa);
uint32_t taint2_query_tcn_reg(int reg_num, int offset);
uint32_t taint2_query_tcn_llvm(int reg_num, int offset);

void taint2_labelset_spit(LabelSetP ls);

void taint2_labelset_ram_iter(uint64_t pa, int (*app)(uint32_t el, void *stuff1), void *stuff2);
void taint2_labelset_reg_iter(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2);
void taint2_labelset_llvm_iter(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2);
void taint2_labelset_iter(LabelSetP ls,  int (*app)(uint32_t el, void *stuff1), void *stuff2) ;

uint32_t *taint2_labels_applied(void);
uint32_t taint2_num_labels_applied(void);

void taint2_track_taint_state(void);

}

#include <llvm/PassManager.h>
#include <llvm/PassRegistry.h>
#include <llvm/Analysis/Verifier.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>

#include "tcg-llvm.h"
#include "panda_memlog.h"

#include "shad_dir_32.h"
#include "shad_dir_64.h"
#include "llvm_taint_lib.h"
#include "fast_shad.h"
#include "taint_ops.h"
#include "taint2.h"

#include "panda_hypercall_struct.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {


bool init_plugin(void *);
void uninit_plugin(void *);
int after_block_translate(CPUState *env, TranslationBlock *tb);
bool before_block_exec_invalidate_opt(CPUState *env, TranslationBlock *tb);
int before_block_exec(CPUState *env, TranslationBlock *tb);
int after_block_exec(CPUState *env, TranslationBlock *tb,
    TranslationBlock *next_tb);
//int cb_cpu_restore_state(CPUState *env, TranslationBlock *tb);
int guest_hypercall_callback(CPUState *env);

int phys_mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf);
int phys_mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr,
        target_ulong size, void *buf);

void taint_state_changed(FastShad *, uint64_t);
PPP_PROT_REG_CB(on_taint_change);
PPP_CB_BOILERPLATE(on_taint_change);

bool track_taint_state = false;

}

Shad *shadow = NULL; // Global shadow memory

// Pointer passed in init_plugin()
void *plugin_ptr = NULL;

// Our pass manager to derive taint ops
llvm::FunctionPassManager *FPM = NULL;

// Taint function pass.
llvm::PandaTaintFunctionPass *PTFP = NULL;

// For now, taint becomes enabled when a label operation first occurs, and
// becomes disabled when a query operation subsequently occurs
bool taintEnabled = false;

// Lets us know right when taint was disabled
bool taintJustDisabled = false;

// Taint memlog
static taint2_memlog taint_memlog;

// Configuration
bool tainted_pointer = true;
static TaintGranularity granularity;
static TaintLabelMode mode;
bool optimize_llvm = true;
extern bool inline_taint;


/*
 * These memory callbacks are only for whole-system mode.  User-mode memory
 * accesses are captured by IR instrumentation.
 */
int phys_mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    /*if (size == 4) {
        printf("pmem: " TARGET_FMT_lx "\n", addr);
    }*/
    taint_memlog_push(&taint_memlog, addr);
    return 0;
}

int phys_mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr,
        target_ulong size, void *buf){
    /*if (size == 4) {
        printf("pmem: " TARGET_FMT_lx "\n", addr);
    }*/
    taint_memlog_push(&taint_memlog, addr);
    return 0;
}

void verify(void) {
    llvm::Module *mod = tcg_llvm_ctx->getModule();
    std::string err;
    if(verifyModule(*mod, llvm::AbortProcessAction, &err)){
        printf("%s\n", err.c_str());
    }
}

void __taint2_enable_taint(void) {
    if(taintEnabled) {return;}
    printf ("taint2: __taint_enable_taint\n");
    taintEnabled = true;
    panda_cb pcb;

    pcb.after_block_translate = after_block_translate;
    panda_register_callback(plugin_ptr, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);
    pcb.before_block_exec_invalidate_opt = before_block_exec_invalidate_opt;
    panda_register_callback(plugin_ptr, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, pcb);
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(plugin_ptr, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    pcb.after_block_exec = after_block_exec;
    panda_register_callback(plugin_ptr, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
    pcb.phys_mem_read = phys_mem_read_callback;
    panda_register_callback(plugin_ptr, PANDA_CB_PHYS_MEM_READ, pcb);
    pcb.phys_mem_write = phys_mem_write_callback;
    panda_register_callback(plugin_ptr, PANDA_CB_PHYS_MEM_WRITE, pcb);
/*
    pcb.cb_cpu_restore_state = cb_cpu_restore_state;
    panda_register_callback(plugin_ptr, PANDA_CB_CPU_RESTORE_STATE, pcb);
    // for hd and network taint
    pcb.replay_hd_transfer = cb_replay_hd_transfer_taint;
    panda_register_callback(plugin_ptr, PANDA_CB_REPLAY_HD_TRANSFER, pcb);
    pcb.replay_net_transfer = cb_replay_net_transfer_taint;
    panda_register_callback(plugin_ptr, PANDA_CB_REPLAY_NET_TRANSFER, pcb);
    pcb.replay_before_cpu_physical_mem_rw_ram = cb_replay_cpu_physical_mem_rw_ram;
    panda_register_callback(plugin_ptr, PANDA_CB_REPLAY_BEFORE_CPU_PHYSICAL_MEM_RW_RAM, pcb);
*/
    panda_enable_precise_pc(); //before_block_exec requires precise_pc for panda_current_asid

    if (!execute_llvm){
        panda_enable_llvm();
    }
    panda_enable_llvm_helpers();

    /*
     * Taint processor initialization
     */

    shadow = tp_init(TAINT_BYTE_LABEL, TAINT_GRANULARITY_BYTE);
    if (shadow == NULL){
        printf("Error initializing shadow memory...\n");
        exit(1);
    }

    // Initialize memlog.
    memset(&taint_memlog, 0, sizeof(taint_memlog));

    llvm::Module *mod = tcg_llvm_ctx->getModule();
    FPM = tcg_llvm_ctx->getFunctionPassManager();

    // Add the taint analysis pass to our taint pass manager
    PTFP = new llvm::PandaTaintFunctionPass(shadow, &taint_memlog);
    FPM->add(PTFP);

    if (optimize_llvm) {
        printf("taint2: Adding default optimizations (-O1).\n");
        llvm::PassManagerBuilder Builder;
        Builder.OptLevel = 1;
        Builder.SizeLevel = 0;
        Builder.populateFunctionPassManager(*FPM);
    }

    FPM->doInitialization();

    // Populate module with helper function taint ops
    for (auto i = mod->begin(); i != mod->end(); i++){
        if (!i->isDeclaration()) PTFP->runOnFunction(*i);
    }

    printf("taint2: Done processing helper functions for taint.\n");

    std::string err;
    if(verifyModule(*mod, llvm::AbortProcessAction, &err)){
        printf("%s\n", err.c_str());
        exit(1);
    }

    //tcg_llvm_write_module(tcg_llvm_ctx, "/tmp/llvm-mod.bc");

    printf("taint2: Done verifying module. Running...\n");
}

// Derive taint ops
int after_block_translate(CPUState *env, TranslationBlock *tb){

    if (taintEnabled){
        assert(tb->llvm_function);
        // taintfp will make sure it never runs twice.
        //FPM->run(*(tb->llvm_function));
        //tb->llvm_function->dump();
    }

    return 0;
}

// Execute taint ops
int after_block_exec(CPUState *env, TranslationBlock *tb,
        TranslationBlock *next_tb){

    if (taintJustDisabled){
        taintJustDisabled = false;
        execute_llvm = 0;
        generate_llvm = 0;
        panda_do_flush_tb();
        panda_disable_memcb();
	//	mytimer_start(ttimer);
        return 0;
    }

    return 0;
}

__attribute__((unused)) static void print_labels(uint32_t el, void *stuff) {
    printf("%d ", el);
}

__attribute__((unused)) static void record_bit(uint32_t el, void *array) {
    *(uint64_t *)array |= 1 << el;
}

#ifdef TARGET_ARM
// R0 is command (label or query)
// R1 is buf_start
// R2 is length
// R3 is offset (not currently implemented)
void arm_hypercall_callback(CPUState *env){
    //target_ulong buf_start = env->regs[1];
    //target_ulong buf_len = env->regs[2];

    if (env->regs[0] == 7 || env->regs[0] == 8){ //Taint label
        if (!taintEnabled){
            printf("Taint plugin: Label operation detected @ %lu\n", rr_get_guest_instr_count());
            printf("Enabling taint processing\n");
            __taint2_enable_taint();
        }

        // FIXME: do labeling here.
    }

    else if (env->regs[0] == 9){ //Query taint on label
        if (taintEnabled){
            printf("Taint plugin: Query operation detected @ %lu\n", rr_get_guest_instr_count());
            //Addr a = make_maddr(buf_start);
            //bufplot(env, shadow, &a, (int)buf_len);
        }
        //printf("Disabling taint processing\n");
        //taintEnabled = false;
        //taintJustDisabled = true;
        //printf("Label occurrences on HD: %d\n", shad_dir_occ_64(shadow->hd));
    }
}
#endif //TARGET_ARM


int label_spit(uint32_t el, void *stuff) {
    printf ("%d ", el);
    return 0;
}


#define MAX_EL_ARR_IND 1000000
uint32_t el_arr_ind = 0;

// used by hypercall to pack pandalog array with query result
int collect_query_labels_pandalog(uint32_t el, void *stuff) {
    uint32_t *label = (uint32_t *) stuff;
    assert (el_arr_ind < MAX_EL_ARR_IND);
    label[el_arr_ind++] = el;
    return 0;
}

#define PANDA_MAX_STRING_READ 256

void panda_virtual_string_read(CPUState *env, target_ulong vaddr, char *str) {
    for (uint32_t i=0; i<PANDA_MAX_STRING_READ; i++) {
        uint8_t c;
        panda_virtual_memory_rw(env, vaddr + i, &c, 1, false);
        str[i] = c;
        if (c==0) break;
    }
    str[PANDA_MAX_STRING_READ-1] = 0;
}


void lava_src_info_pandalog(PandaHypercallStruct phs) {
    extern CPUState *cpu_single_env;
    CPUState *env = cpu_single_env;
    // write out src-level info    
    Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;                    
    Panda__SrcInfo *si = (Panda__SrcInfo *) malloc(sizeof(Panda__SrcInfo));
    *si = PANDA__SRC_INFO__INIT;
    char filenameStr[500];
    char astNodeStr[500];
    panda_virtual_string_read(env, phs.src_filename, filenameStr);
    panda_virtual_string_read(env, phs.src_ast_node_name, astNodeStr);
    si->filename = filenameStr;
    si->astnodename = astNodeStr;
    si->linenum = phs.src_linenum;
    ple = PANDA__LOG_ENTRY__INIT;
    ple.src_info = si;
    pandalog_write_entry(&ple);
    free(si);
} 



// used to ensure that we only write a label sets to pandalog once
std::set < LabelSetP > ls_returned;



// queries taint on this addr and
// if anything is tainted returns 1, else returns 0
// if there is taint, we write an entry to the pandalog. 
uint8_t __taint2_query_pandalog (Addr a) {
    uint8_t saw_taint = 0;
    LabelSetP ls = tp_query(shadow, a);
    if (ls) {
        saw_taint = 1;
        if (ls_returned.count(ls) == 0) {
            // we only want to actually write a particular set contents to pandalog once
            // this ls hasn't yet been written to pandalog
            // write out mapping from ls pointer to labelset contents
            // as its own separate log entry
            ls_returned.insert(ls);
            Panda__TaintQueryUniqueLabelSet *tquls = (Panda__TaintQueryUniqueLabelSet *) malloc (sizeof (Panda__TaintQueryUniqueLabelSet));
            *tquls = PANDA__TAINT_QUERY_UNIQUE_LABEL_SET__INIT;
            tquls->ptr = (uint64_t) ls;
            tquls->n_label = ls_card(ls);
            tquls->label = (uint32_t *) malloc (sizeof(uint32_t) * tquls->n_label);
            el_arr_ind = 0;
            tp_ls_iter(ls, collect_query_labels_pandalog, (void *) tquls->label);
            Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
            ple.taint_query_unique_label_set = tquls;
            pandalog_write_entry(&ple);
            free (tquls->label);
            free (tquls);
        }
        // safe to refer to the set by the pointer in this next message
        Panda__TaintQuery *tq = (Panda__TaintQuery *) malloc(sizeof(Panda__TaintQuery));
        *tq = PANDA__TAINT_QUERY__INIT;
        tq->ptr = (uint64_t) ls;
        tq->tcn = taint2_query_tcn(a);
        //        tq->offset = offset;
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        ple.taint_query = tq;
        pandalog_write_entry(&ple);
        free(tq);
    }    
    return saw_taint;
}





// hypercall-initiated taint query of some src-level extent
void lava_taint_query (PandaHypercallStruct phs) {
    extern CPUState *cpu_single_env;
    CPUState *env = cpu_single_env;
    if  (taintEnabled && (taint2_num_labels_applied() > 0)){
        // okay, taint is on and some labels have actually been applied 
        // is there *any* taint on this extent
        uint32_t num_tainted = 0;
        for (uint32_t offset=0; offset<phs.len; offset++) {
            uint32_t va = phs.buf + offset;
            uint32_t pa =  panda_virt_to_phys(env, va);
            if ((int) pa != -1) {                         
                Addr a = make_maddr(pa);
                if (taint2_query(a)) {
                    num_tainted ++;
                }
            }
        }
        if (num_tainted) {
            // ok at least one byte in the extent is tainted
            // 1. write the pandalog entry that tells us something was tainted on this extent
            Panda__TaintQueryHypercall *tqh = (Panda__TaintQueryHypercall *) malloc (sizeof (Panda__TaintQueryHypercall));
            *tqh = PANDA__TAINT_QUERY_HYPERCALL__INIT;
            tqh->buf = phs.buf;
            tqh->len = phs.len;
            tqh->num_tainted = num_tainted;
            // obtain the actual data out of memory
            // NOTE: first 32 bytes only!
            uint32_t data[32];
            uint32_t n = phs.len;
            if (32 < phs.len) n = 32;
            for (uint32_t i=0; i<n; i++) {
                data[i] = 0;
                uint8_t c;
                panda_virtual_memory_rw(env, phs.buf+i, &c, 1, false);
                data[i] = c;
            }
            tqh->n_data = n;
            tqh->data = data;
            Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
            ple.taint_query_hypercall = tqh;
            pandalog_write_entry(&ple);
            free(tqh);
            // 2. write out src-level info
            lava_src_info_pandalog(phs);
            // 3. write out callstack info
            callstack_pandalog();
            // 4. iterate over the bytes in the extent and pandalog detailed info about taint
            for (uint32_t offset=0; offset<phs.len; offset++) {
                uint32_t va = phs.buf + offset;
                uint32_t pa =  panda_virt_to_phys(env, va);
                if ((int) pa != -1) {                         
                    Addr a = make_maddr(pa);
                    if (taint2_query(a)) {
                        __taint2_query_pandalog(a);
                    }
                }
            }
        }
    }
}


void lava_attack_point(PandaHypercallStruct phs) {
    Panda__AttackPoint *ap = (Panda__AttackPoint *) malloc (sizeof (Panda__AttackPoint));
    *ap = PANDA__ATTACK_POINT__INIT;
    ap->info = "memcpy";
    Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
    ple.attack_point = ap;
    pandalog_write_entry(&ple);
    free(ap);
    // write out src-level info
    lava_src_info_pandalog(phs);
    // write out callstack info
    callstack_pandalog();
}    


#ifdef TARGET_I386
// Support all features of label and query program
void i386_hypercall_callback(CPUState *env){


#if 0
    if (EAX == 0xabcd) {
        printf ("\n hypercall pc=0x%x\n", (int) panda_current_pc(env));
        for (uint32_t i=0; i<8; i++) {
            printf ("reg[%d] = 0x%x\n", i, (int) env->regs[i]);
        }
    }   
#endif


    //printf("taint2: Hypercall! B " TARGET_FMT_lx " C " TARGET_FMT_lx " D " TARGET_FMT_lx "\n",
    //        env->regs[R_EBX], env->regs[R_ECX], env->regs[R_EDX]);

#if 0
    // Label op.
    // EBX contains addr of that data
    // ECX contains size of data
    // EDX contains the label; ~0UL for autoenc.
    if ((env->regs[R_EAX] == 7 || env->regs[R_EAX] == 8)) {
        printf ("hypercall -- EAX=0x%x\n", EAX);

        target_ulong addr = panda_virt_to_phys(env, env->regs[R_EBX]);
        target_ulong size = env->regs[R_ECX];
        target_ulong label = env->regs[R_EDX];
        if (!taintEnabled){
            printf("taint2: Label operation detected @ %lu\n",
                    rr_get_guest_instr_count());
            printf("taint2: Labeling " TARGET_FMT_lx " to " TARGET_FMT_lx
                    " with label " TARGET_FMT_lx ".\n", addr, addr + size, label);
            __taint2_enable_taint();
        }

        LabelSetP ls = NULL;
        if (label != (target_ulong)~0UL) {
            ls = label_set_singleton(label);
        } // otherwise autoinc.
        qemu_log_mask(CPU_LOG_TAINT_OPS, "label: %lx[%lx+%lx] <- %lx (%lx)\n",
                (uint64_t)shadow->ram, (uint64_t)addr, (uint64_t)size, (uint64_t)label,
                (uint64_t)ls);
        for (unsigned i = 0; i < size; i++) {
            //printf("label %u\n", i);
            shadow->ram->set(addr + i,
                    label_set_singleton(i));
        }
    }
#endif

    
    if (pandalog && env->regs[R_EAX] == 0xabcd) {
        // LAVA Hypercall
        target_ulong addr = panda_virt_to_phys(env, ECX);
        if ((int)addr == -1) {
            printf ("panda hypercall with ptr to invalid PandaHypercallStruct: vaddr=0x%x paddr=0x%x\n",
                    (uint32_t) ECX, (uint32_t) addr);
        }
        else {
            PandaHypercallStruct phs;
            panda_virtual_memory_rw(env, ECX, (uint8_t *) &phs, sizeof(phs), false);
            if  (phs.action == 11) {
                // it's a lava query
                lava_taint_query(phs);               
            }
            if (phs.action == 12) {
                // it's an attack point sighting
                lava_attack_point(phs);
            }
        }    
    }
}
#endif // TARGET_I386

int guest_hypercall_callback(CPUState *env){
#ifdef TARGET_I386
    i386_hypercall_callback(env);
#endif

#ifdef TARGET_ARM
    arm_hypercall_callback(env);
#endif

    return 1;
}

// Called whenever the taint state changes.
void taint_state_changed(FastShad *fast_shad, uint64_t shad_addr) {
    Addr addr;
    if (fast_shad == shadow->llv) {
        addr = make_laddr(shad_addr / MAXREGSIZE, shad_addr % MAXREGSIZE);
    } else if (fast_shad == shadow->ram) {
        addr = make_maddr(shad_addr);
    } else if (fast_shad == shadow->grv) {
        addr = make_greg(shad_addr / sizeof(target_ulong), shad_addr % sizeof(target_ulong));
    } else if (fast_shad == shadow->gsv) {
        addr.typ = GSPEC;
        addr.val.gs = shad_addr;
        addr.off = 0;
        addr.flag = (AddrFlag)0;
    } else if (fast_shad == shadow->ret) {
        addr.typ = RET;
        addr.val.ret = 0;
        addr.off = shad_addr;
        addr.flag = (AddrFlag)0;
    } else return;

    PPP_RUN_CB(on_taint_change, addr);
}

bool __taint2_enabled() {
    return taintEnabled;
}

// label this phys addr in memory with this label
void __taint2_label_ram(uint64_t pa, uint32_t l) {
    tp_label_ram(shadow, pa, l);
}




uint32_t __taint2_query(Addr a) {
    LabelSetP ls = tp_query(shadow, a);
    return ls_card(ls);
}

// if phys addr pa is untainted, return 0.
// else returns label set cardinality
uint32_t __taint2_query_ram(uint64_t pa) {
    LabelSetP ls = tp_query_ram(shadow, pa);
    return ls_card(ls);
}


uint32_t __taint2_query_reg(int reg_num, int offset) {
    LabelSetP ls = tp_query_reg(shadow, reg_num, offset);
    return ls_card(ls);
}

uint32_t __taint2_query_llvm(int reg_num, int offset) {
    LabelSetP ls = tp_query_llvm(shadow, reg_num, offset);
    return ls_card(ls);
}



uint32_t __taint2_query_tcn(Addr a) {
    return tp_query_tcn(shadow, a);
}

uint32_t __taint2_query_tcn_ram(uint64_t pa) {
    return tp_query_tcn_ram(shadow, pa);
}

uint32_t __taint2_query_tcn_reg(int reg_num, int offset) {
    return tp_query_tcn_reg(shadow, reg_num, offset);
}

uint32_t __taint2_query_tcn_llvm(int reg_num, int offset) {
    return tp_query_tcn_llvm(shadow, reg_num, offset);
}


uint32_t *__taint2_labels_applied(void) {
    return tp_labels_applied();
}

uint32_t __taint2_num_labels_applied(void) {
    return tp_num_labels_applied();
}




void __taint2_delete_ram(uint64_t pa) {
    tp_delete_ram(shadow, pa);
}

void __taint2_labelset_spit(LabelSetP ls) {
    std::set<uint32_t> rendered(label_set_render_set(ls));
    for (uint32_t l : rendered) {
        printf("%u ", l);
    }
    printf("\n");
}


void __taint2_labelset_iter(LabelSetP ls,  int (*app)(uint32_t el, void *stuff1), void *stuff2) {
    tp_ls_iter(ls, app, stuff2);
}



void __taint2_labelset_ram_iter(uint64_t pa, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
    tp_ls_ram_iter(shadow, pa, app, stuff2);
}


void __taint2_labelset_reg_iter(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
    tp_ls_reg_iter(shadow, reg_num, offset, app, stuff2);
}


void __taint2_labelset_llvm_iter(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
    tp_ls_llvm_iter(shadow, reg_num, offset, app, stuff2);
}

void __taint2_track_taint_state(void) {
    track_taint_state = true;
}



////////////////////////////////////////////////////////////////////////////////////
// C API versions


void taint2_enable_taint(void) {
  __taint2_enable_taint();
}

int taint2_enabled(void) {
  return __taint2_enabled();
}

void taint2_label_ram(uint64_t pa, uint32_t l) {
    __taint2_label_ram(pa, l);
}


uint8_t taint2_query_pandalog (Addr a) {
    return __taint2_query_pandalog(a);
}

uint32_t taint2_query(Addr a) {
    return __taint2_query(a);
}

uint32_t taint2_query_ram(uint64_t pa) {
    return __taint2_query_ram(pa);
}


uint32_t taint2_query_tcn(Addr a) {
    return __taint2_query_tcn(a);
}

uint32_t taint2_query_tcn_ram(uint64_t pa) {
    return __taint2_query_tcn_ram(pa);
}

uint32_t taint2_query_tcn_reg(int reg_num, int offset) {
    return __taint2_query_tcn_reg(reg_num, offset);
}

uint32_t taint2_query_tcn_llvm(int reg_num, int offset) {
    return __taint2_query_tcn_llvm(reg_num, offset);
}




void taint2_delete_ram(uint64_t pa) {
  __taint2_delete_ram(pa);
}

uint32_t taint2_query_reg(int reg_num, int offset) {
  return __taint2_query_reg(reg_num, offset);
}

uint32_t taint2_query_llvm(int reg_num, int offset) {
  return __taint2_query_llvm(reg_num, offset);
}

void taint2_labelset_spit(LabelSetP ls) {
    return __taint2_labelset_spit(ls);
}

void taint2_labelset_iter(LabelSetP ls,  int (*app)(uint32_t el, void *stuff1), void *stuff2) {
    __taint2_labelset_iter(ls, app, stuff2);
}


void taint2_labelset_ram_iter(uint64_t pa, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
    __taint2_labelset_ram_iter(pa, app, stuff2);
}


void taint2_labelset_reg_iter(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
    __taint2_labelset_reg_iter(reg_num, offset, app, stuff2);
}


void taint2_labelset_llvm_iter(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
    __taint2_labelset_llvm_iter(reg_num, offset, app, stuff2);
}

uint32_t *taint2_labels_applied(void) {
    return __taint2_labels_applied();
}


uint32_t taint2_num_labels_applied(void) {
    return __taint2_num_labels_applied();
}

void taint2_track_taint_state(void) {
    __taint2_track_taint_state();
}


////////////////////////////////////////////////////////////////////////////////////

int before_block_exec(CPUState *env, TranslationBlock *tb) {



    return 0;
}



void prstr(CPUState *env, uint32_t o, uint32_t va) {

    uint32_t ptr;
    panda_virtual_memory_rw(env, va+o, (uint8_t *) &ptr, 4, false);
    printf ("ptr=0x%x\n", ptr);
    uint8_t buf[16];
    panda_virtual_memory_rw(env, ptr, buf, 16, false);
    buf[15] = 0;
    printf ("o=%d : [%s]\n", o, buf);
}



bool before_block_exec_invalidate_opt(CPUState *env, TranslationBlock *tb) {


    //if (!taintEnabled) __taint_enable_taint();

#ifdef TAINTDEBUG
    //printf("%s\n", tcg_llvm_get_func_name(tb));
#endif

    if (taintEnabled) {
        if (!tb->llvm_tc_ptr) {
            return true;
        } else {
            //tb->llvm_function->dump();
            return false;
        }
    }
    return false;
}

bool init_plugin(void *self) {
    printf("Initializing taint plugin\n");
    plugin_ptr = self;
    panda_cb pcb;
    panda_enable_memcb();
    panda_disable_tb_chaining();
    pcb.guest_hypercall = guest_hypercall_callback;
    panda_register_callback(self, PANDA_CB_GUEST_HYPERCALL, pcb);
    pcb.before_block_exec_invalidate_opt = before_block_exec_invalidate_opt;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, pcb);
    /*
    pcb.replay_handle_packet = handle_packet;
    panda_register_callback(plugin_ptr, PANDA_CB_REPLAY_HANDLE_PACKET, pcb);
    */

    panda_arg_list *args = panda_get_args("taint2");
    tainted_pointer = !panda_parse_bool(args, "no_tp");
    inline_taint = panda_parse_bool(args, "inline");
    if (inline_taint) {
        printf("taint2: Inlining taint ops by default.\n");
    } else {
        printf("taint2: Instructed not to inline taint ops.\n");
    }
    if (panda_parse_bool(args, "binary")) mode = TAINT_BINARY_LABEL;
    if (panda_parse_bool(args, "word")) granularity = TAINT_GRANULARITY_WORD;
    optimize_llvm = panda_parse_bool(args, "opt");

    panda_require("callstack_instr");
    assert(init_callstack_instr_api());

    return true;
}



void uninit_plugin(void *self) {

    printf ("uninit taint plugin\n");

    if (shadow) tp_free(shadow);

    panda_disable_llvm();
    panda_disable_memcb();
    panda_enable_tb_chaining();

}
