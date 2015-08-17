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

    //#define TAINT_LEGACY_HYPERCALL // for use with replays that use old hypercall

extern int loglevel;

// For the C API to taint accessible from other plugins
void taint2_enable_taint(void);
int taint2_enabled(void);
void taint2_label_ram(uint64_t pa, uint32_t l) ;
void taint2_add_taint_ram_pos(CPUState *env, uint64_t addr, uint32_t length);
void taint2_add_taint_ram_single_label(CPUState *env, uint64_t addr,
    uint32_t length, long label);
void taint2_delete_ram(uint64_t pa);

   
Panda__TaintQuery *taint2_query_pandalog (Addr addr, uint32_t offset);
void pandalog_taint_query_free(Panda__TaintQuery *tq);

uint32_t taint2_query(Addr a);
uint32_t taint2_query_ram(uint64_t pa);
uint32_t taint2_query_reg(int reg_num, int offset);
uint32_t taint2_query_llvm(int reg_num, int offset);


uint32_t taint2_query_tcn(Addr a);
uint32_t taint2_query_tcn_ram(uint64_t pa);
uint32_t taint2_query_tcn_reg(int reg_num, int offset);
uint32_t taint2_query_tcn_llvm(int reg_num, int offset);

uint64_t taint2_query_cb_mask(Addr a, uint8_t size);

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

#ifdef PANDA_LAVA
#include "../../../../lava/include/panda_hypercall_struct.h"
#else
#include "panda_hypercall_struct.h"
#endif

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

void taint_state_changed(FastShad *, uint64_t, uint64_t);
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
        uint8_t c = 0;
        if (-1 == panda_virtual_memory_rw(env, vaddr + i, &c, 1, false)) {
            printf("Can't access memory at " TARGET_FMT_lx "\n", vaddr + i);
            str[i] = 0;
            break;
        }
        str[i] = c;
        if (c==0) break;
    }
    str[PANDA_MAX_STRING_READ-1] = 0;
}

/*
  Construct pandalog msg for src-level info
 */

Panda__SrcInfo *pandalog_src_info_create(PandaHypercallStruct phs) {
    Panda__SrcInfo *si = (Panda__SrcInfo *) malloc(sizeof(Panda__SrcInfo));
    *si = PANDA__SRC_INFO__INIT;
    si->filename = phs.src_filename;
    si->astnodename = phs.src_ast_node_name;
    si->linenum = phs.src_linenum;
#ifdef PANDA_LAVA
    si->has_insertionpoint = 0;
    if (phs.insertion_point) {
        si->has_insertionpoint = 1;
        si->insertionpoint = phs.insertion_point;
    }
#endif
    return si;
} 


// used to ensure that we only write a label sets to pandalog once
std::set < LabelSetP > ls_returned;


/*
  Queries taint on this addr and return a Panda__TaintQuery 
  data structure containing results of taint query.

  if there is no taint set associated with that address, return NULL.
  
  NOTE: offset is offset into the thing that was queried.
  so, e.g., if that thing was a buffer and the query came
  from guest source code, then offset is where we are in the buffer.
  offset isn't intended to be used in any other way than to
  propagate this to the offset part of the pandalog entry for 
  a taint query.
  In other words, this offset is not necessarily related to a.off

  ugh.  
*/ 

Panda__TaintQuery *__taint2_query_pandalog (Addr a, uint32_t offset) {
    LabelSetP ls = tp_query(shadow, a);
    if (ls) {
        Panda__TaintQuery *tq = (Panda__TaintQuery *) malloc(sizeof(Panda__TaintQuery));
        *tq = PANDA__TAINT_QUERY__INIT;        
        if (ls_returned.count(ls) == 0) {
            // we only want to actually write a particular set contents to pandalog once
            // this ls hasn't yet been written to pandalog
            // write out mapping from ls pointer to labelset contents
            // as its own separate log entry
            ls_returned.insert(ls);
            Panda__TaintQueryUniqueLabelSet *tquls =
                (Panda__TaintQueryUniqueLabelSet *) 
                malloc (sizeof (Panda__TaintQueryUniqueLabelSet));                
            *tquls = PANDA__TAINT_QUERY_UNIQUE_LABEL_SET__INIT;
            tquls->ptr = (uint64_t) ls;
            tquls->n_label = ls_card(ls);
            tquls->label = (uint32_t *) malloc (sizeof(uint32_t) * tquls->n_label);
            el_arr_ind = 0;
            tp_ls_iter(ls, collect_query_labels_pandalog, (void *) tquls->label);
            tq->unique_label_set = tquls;
        }
        tq->ptr = (uint64_t) ls;
        tq->tcn = taint2_query_tcn(a);
        // offset within larger thing being queried
        tq->offset = offset;
        return tq;
    }    
    return NULL;
}


void __pandalog_taint_query_free(Panda__TaintQuery *tq) {
    if (tq->unique_label_set) {
        if (tq->unique_label_set->label) {
            free(tq->unique_label_set->label);
        }
        free(tq->unique_label_set);
    }
}


// max length of strnlen or taint query
#define LAVA_TAINT_QUERY_MAX_LEN 32

// hypercall-initiated taint query of some src-level extent
void lava_taint_query (PandaHypercallStruct phs) {
    extern CPUState *cpu_single_env;
    CPUState *env = cpu_single_env;

    if  (pandalog && taintEnabled && (taint2_num_labels_applied() > 0)){
        // okay, taint is on and some labels have actually been applied 
        // is there *any* taint on this extent
        uint32_t num_tainted = 0;
        bool is_strnlen = ((int) phs.len == -1);
        uint32_t offset=0;
        while (true) {
        //        for (uint32_t offset=0; offset<phs.len; offset++) {
            uint32_t va = phs.buf + offset;
            uint32_t pa =  panda_virt_to_phys(env, va);
            if (is_strnlen) {
                uint8_t c;
                panda_virtual_memory_rw(env, pa, &c, 1, false);
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
            if (is_strnlen && (offset == LAVA_TAINT_QUERY_MAX_LEN)) break;
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
            uint32_t data[LAVA_TAINT_QUERY_MAX_LEN];
            uint32_t n = len;
            // grab at most X bytes from memory to pandalog
            // this is just a snippet.  we dont want to write 1M buffer
            if (LAVA_TAINT_QUERY_MAX_LEN < len) n = LAVA_TAINT_QUERY_MAX_LEN;
            for (uint32_t i=0; i<n; i++) {
                data[i] = 0;
                uint8_t c;
                panda_virtual_memory_rw(env, phs.buf+i, &c, 1, false);
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
            // 4. iterate over the bytes in the extent and pandalog detailed info about taint
            std::vector<Panda__TaintQuery *> tq;
            for (uint32_t offset=0; offset<len; offset++) {
                uint32_t va = phs.buf + offset;
                uint32_t pa =  panda_virt_to_phys(env, va);
                if ((int) pa != -1) {                         
                    Addr a = make_maddr(pa);
                    if (taint2_query(a)) {
                        tq.push_back(__taint2_query_pandalog(a, offset));
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
                __pandalog_taint_query_free(tqh->taint_query[i]);
            }
            free(tqh);
        }
    }
}


void lava_attack_point(PandaHypercallStruct phs) {
    if (pandalog) {
        Panda__AttackPoint *ap = (Panda__AttackPoint *) malloc (sizeof (Panda__AttackPoint));
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


#ifdef TARGET_I386
// Support all features of label and query program
void i386_hypercall_callback(CPUState *env){
    if (taintEnabled && pandalog) {
        // LAVA Hypercall
#ifdef TAINT_LEGACY_HYPERCALL
        target_ulong buf_start = EBX;
        target_ulong buf_len = ECX;
        long label = EDI;

        // call to label data
        // EBX contains addr of that data
        // ECX contains size of data
        // EDI is the label integer
        // EDX = starting offset (for positional labels only)
        //     -mostly not used, this is managed in pirate_utils
        if (EAX == 7 || EAX == 8){
            if (!taintEnabled){
                printf("Taint plugin: Label operation detected\n");
                printf("Enabling taint processing\n");
                __taint2_enable_taint();
            }
            if (EAX == 7){
                // Standard buffer label
                printf("taint2: single taint label\n");
                taint2_add_taint_ram_single_label(env, (uint64_t)buf_start,
                    (int)buf_len, label);
            }
            else if (EAX == 8){
                // Positional buffer label
                printf("taint2: positional taint label\n");
                taint2_add_taint_ram_pos(env, (uint64_t)buf_start, (int)buf_len);
            }
        }

        /*
        //mz Query taint on this buffer
        //mz EBX = start of buffer (VA)
        //mz ECX = size of buffer (bytes)
        // EDX = starting offset - for file queries
        //    -mostly not used, this is managed in pirate_utils
        else if (env->regs[R_EAX] == 9){ //Query taint on label
            if (taintEnabled){
                printf("Taint plugin: Query operation detected\n");
                Addr a = make_maddr(buf_start);
                bufplot(env, shadow, &a, (int)buf_len);
            }
            //printf("Disabling taint processing\n");
            //taintEnabled = false;
            //taintJustDisabled = true;
            //printf("Label occurrences on HD: %d\n", shad_dir_occ_64(shadow->hd));
        }
        else if (env->regs[R_EAX] == 10){
            // Guest util done - reset positional label counter
            taint_pos_count = 0;
        }
        */
#else
        target_ulong addr = panda_virt_to_phys(env, EAX);
        if ((int)addr == -1) {
            printf ("panda hypercall with ptr to invalid PandaHypercallStruct: vaddr=0x%x paddr=0x%x\n",
                    (uint32_t) EAX, (uint32_t) addr);
        }
        else {
            PandaHypercallStruct phs;
            panda_virtual_memory_rw(env, EAX, (uint8_t *) &phs, sizeof(phs), false);
            if (phs.magic == 0xabcd) {
                if  (phs.action == 11) {
                    // it's a lava query
                    lava_taint_query(phs);               
                }
                else if (phs.action == 12) {
                    // it's an attack point sighting
                    lava_attack_point(phs);
                }
                else {
                    printf("Unknown hypercall action %d\n", phs.action);
                }
            }
            else {
                printf ("Invalid magic value in PHS struct: %x != 0xabcd.\n", phs.magic);
            }
        }
#endif // TAINT_LEGACY_HYPERCALL
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
void taint_state_changed(FastShad *fast_shad, uint64_t shad_addr, uint64_t size) {
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

    PPP_RUN_CB(on_taint_change, addr, size);
}

bool __taint2_enabled() {
    return taintEnabled;
}

// label this phys addr in memory with this label
void __taint2_label_ram(uint64_t pa, uint32_t l) {
    tp_label_ram(shadow, pa, l);
}

uint32_t taint_pos_count = 0;

void label_byte(CPUState *env, target_ulong virt_addr, uint32_t label_num) {
    target_phys_addr_t pa = panda_virt_to_phys(env, virt_addr);
    if (pandalog) {
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        ple.has_taint_label_virtual_addr = 1;
        ple.has_taint_label_physical_addr = 1;
        ple.has_taint_label_number = 1;
        ple.taint_label_virtual_addr = virt_addr;
        ple.taint_label_physical_addr = pa;
        ple.taint_label_number = label_num;
        pandalog_write_entry(&ple);
    }
    taint2_label_ram(pa, label_num);
}

// Apply positional taint to a buffer of memory
void taint2_add_taint_ram_pos(CPUState *env, uint64_t addr, uint32_t length){
    for (unsigned i = 0; i < length; i++){
        target_phys_addr_t pa = cpu_get_phys_addr(env, addr + i);
        if (pa == (target_phys_addr_t)(-1)) {
            printf("can't label addr=0x%lx: mmu hasn't mapped virt->phys, "
                "i.e., it isnt actually there.\n", addr +i);
            continue;
        }
        //taint2_label_ram(pa, i + taint_pos_count);
        printf("taint2: adding positional taint label %d\n", i+taint_pos_count);
        label_byte(env, addr+i, i+taint_pos_count);
    }
    taint_pos_count += length;
}

// Apply single label taint to a buffer of memory
void taint2_add_taint_ram_single_label(CPUState *env, uint64_t addr,
        uint32_t length, long label){
    for (unsigned i = 0; i < length; i++){
        target_phys_addr_t pa = cpu_get_phys_addr(env, addr + i);
        if (pa == (target_phys_addr_t)(-1)) {
            printf("can't label addr=0x%lx: mmu hasn't mapped virt->phys, "
                "i.e., it isnt actually there.\n", addr +i);
            continue;
        }
        //taint2_label_ram(pa, label);
        printf("taint2: adding single taint label %lu\n", label);
        label_byte(env, addr+i, label);
    }
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

uint64_t __taint2_query_cb_mask(Addr a, uint8_t size) {
    return tp_query_cb_mask(shadow, a, size);
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


Panda__TaintQuery *taint2_query_pandalog (Addr addr, uint32_t offset) {
    return __taint2_query_pandalog(addr, offset);
}

void pandalog_taint_query_free(Panda__TaintQuery *tq) {
    __pandalog_taint_query_free(tq);
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

uint64_t taint2_query_cb_mask(Addr a, uint8_t size) {
    return __taint2_query_cb_mask(a, size);
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
