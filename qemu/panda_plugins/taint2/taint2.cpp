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

extern "C" {

#include <sys/time.h>

#include "qemu-common.h"
#include "cpu-all.h"
#include "panda_plugin.h"
#include "panda_common.h"
#include "panda/network.h"
#include "rr_log.h"
#include "cpu.h"

#include "fast_shad.h"
#include "taint_ops.h"

extern int loglevel;

// For the C API to taint accessible from other plugins
void taint_enable_taint(void);
void taint_label_ram(uint64_t pa, uint32_t l) ;
uint32_t taint_query_ram(uint64_t pa);

}

#include <llvm/PassManager.h>
#include <llvm/PassRegistry.h>
#include <llvm/Analysis/Verifier.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>

#include "tcg-llvm.h"
#include "panda_memlog.h"

#include "shad_dir_32.h"
#include "shad_dir_64.h"
#include "llvm_taint_lib.h"
#include "taint2.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {


bool init_plugin(void *);
void uninit_plugin(void *);
int before_block_exec(CPUState *env, TranslationBlock *tb);
bool before_block_exec_invalidate_opt(CPUState *env, TranslationBlock *tb);
int after_block_exec(CPUState *env, TranslationBlock *tb,
    TranslationBlock *next_tb);
//int cb_cpu_restore_state(CPUState *env, TranslationBlock *tb);
int guest_hypercall_callback(CPUState *env);
/*
// for hd taint
int cb_replay_hd_transfer_taint
  (CPUState *env,
   uint32_t type,
   uint64_t src_addr,
   uint64_t dest_addr,
   uint32_t num_bytes);

int handle_packet(CPUState *env, uint8_t *buf, int size, uint8_t direction,
    uint64_t old_buf_addr);

// for network taint
int cb_replay_net_transfer_taint(CPUState *env, uint32_t type,
   uint64_t src_addr, uint64_t dest_addr, uint32_t num_bytes);

int cb_replay_cpu_physical_mem_rw_ram
  (CPUState *env,
   uint32_t is_write, uint8_t *src_addr, uint64_t dest_addr, uint32_t num_bytes);
*/
int phys_mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf);
int phys_mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr,
        target_ulong size, void *buf);

}

Shad *shadow = NULL; // Global shadow memory

// Pointer passed in init_plugin()
void *plugin_ptr = NULL;

// Our pass manager to derive taint ops
llvm::FunctionPassManager *taintfpm = NULL;

// Taint function pass.
llvm::PandaTaintFunctionPass *PTFP = NULL;

// For now, taint becomes enabled when a label operation first occurs, and
// becomes disabled when a query operation subsequently occurs
bool taintEnabled = false;

// Lets us know right when taint was disabled
bool taintJustDisabled = false;

// Taint memlog
taint2_memlog memlog;

/*
 * These memory callbacks are only for whole-system mode.  User-mode memory
 * accesses are captured by IR instrumentation.
 */
int phys_mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    taint2_memlog_push((uint64_t)&memlog, addr);
    return 0;
}

int phys_mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr,
        target_ulong size, void *buf){
    taint2_memlog_push((uint64_t)&memlog, addr);
    return 0;
}

void verify(void) {
    llvm::Module *mod = tcg_llvm_ctx->getModule();
    std::string err;
    if(verifyModule(*mod, llvm::AbortProcessAction, &err)){
        printf("%s\n", err.c_str());
    }
}

void __taint_enable_taint(void) {
    if(taintEnabled) {return;}
    printf ("__taint_enable_taint\n");
    taintEnabled = true;
    panda_cb pcb;

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

    shadow = tp_init();
    if (shadow == NULL){
        printf("Error initializing shadow memory...\n");
        exit(1);
    }

    // Initialize memlog.
    memset(&memlog, 0, sizeof(memlog));

    llvm::Module *mod = tcg_llvm_ctx->getModule();
    taintfpm = new llvm::FunctionPassManager(mod);

    // Add the taint analysis pass to our taint pass manager
    PTFP = new llvm::PandaTaintFunctionPass(shadow, &memlog);
    taintfpm->add(PTFP);
    taintfpm->doInitialization();

    // Populate module with helper function taint ops
    for (auto i = mod->begin(); i != mod->end(); i++){
        if (!i->isDeclaration()) PTFP->runOnFunction(*i);
    }

    std::string err;
    if(verifyModule(*mod, llvm::AbortProcessAction, &err)){
        printf("%s\n", err.c_str());
        exit(1);
    }

    tcg_llvm_write_module(tcg_llvm_ctx, "/tmp/llvm-mod.bc");
}

// Derive taint ops
int before_block_exec(CPUState *env, TranslationBlock *tb){

    //printf("%s\n", tcg_llvm_get_func_name(tb));

    if (taintEnabled){
        // taintfp will make sure it never runs twice.
        taintfpm->run(*(tb->llvm_function));
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

/*
#ifdef CONFIG_SOFTMMU
// this is for much of the hd taint transfers.
// this gets called from rr_log.c, rr_replay_skipped_calls, RR_CALL_HD_TRANSFER
// case.
int cb_replay_hd_transfer_taint(CPUState *env, uint32_t type, uint64_t src_addr,
        uint64_t dest_addr, uint32_t num_bytes) {
    // Replay hd transfer as taint transfer
    if (taintEnabled) {
        TaintOp top;
        top.typ = BULKCOPYOP;
        top.val.bulkcopy.l = num_bytes;
        switch (type) {
            case HD_TRANSFER_HD_TO_IOB:
#ifdef TAINTDEBUG
                printf("replay_hd_transfer HD_TRANSFER_HD_TO_IOB\n");
#endif
                top.val.bulkcopy.a = make_haddr(src_addr);
                top.val.bulkcopy.b = make_iaddr(dest_addr);
                break;
            case HD_TRANSFER_IOB_TO_HD:
#ifdef TAINTDEBUG
                printf("replay_hd_transfer HD_TRANSFER_IOB_TO_HD\n");
#endif
                top.val.bulkcopy.a = make_iaddr(src_addr);
                top.val.bulkcopy.b = make_haddr(dest_addr);
                break;
            case HD_TRANSFER_PORT_TO_IOB:
#ifdef TAINTDEBUG
                printf("replay_hd_transfer HD_TRANSFER_PORT_TO_IOB\n");
#endif
                top.val.bulkcopy.a = make_paddr(src_addr);
                top.val.bulkcopy.b = make_iaddr(dest_addr);
                break;
            case HD_TRANSFER_IOB_TO_PORT:
#ifdef TAINTDEBUG
                printf("replay_hd_transfer HD_TRANSFER_IOB_TO_PORT\n");
#endif
                top.val.bulkcopy.a = make_iaddr(src_addr);
                top.val.bulkcopy.b = make_paddr(dest_addr);
                break;
            case HD_TRANSFER_HD_TO_RAM:
#ifdef TAINTDEBUG
                printf("replay_hd_transfer HD_TRANSFER_HD_TO_RAM\n");
                printf("\tSource: 0x%lx, Dest: 0x%lx, Len: %d\n",
                    src_addr, dest_addr, num_bytes);
#endif
                top.val.bulkcopy.a = make_haddr(src_addr);
                top.val.bulkcopy.b = make_maddr(dest_addr);
                break;
            case HD_TRANSFER_RAM_TO_HD:
#ifdef TAINTDEBUG
                printf("replay_hd_transfer HD_TRANSFER_RAM_TO_HD\n");
                printf("\tSource: 0x%lx, Dest: 0x%lx, Len: %d\n",
                    src_addr, dest_addr, num_bytes);
#endif
                top.val.bulkcopy.a = make_maddr(src_addr);
                top.val.bulkcopy.b = make_haddr(dest_addr);
                break;
            default:
                printf ("Impossible hd transfer type: %d\n", type);
                assert (1==0);
        }
        // make the taint op buffer bigger if necessary
        tob_resize(&tob_io_thread);
        // add bulk copy corresponding to this hd transfer to buffer
        // of taint ops for io thread.
        tob_op_write(tob_io_thread, &top);
    }
    return 0;
}

int handle_packet(CPUState *env, uint8_t *buf, int size, uint8_t direction,
        uint64_t old_buf_addr){
    switch (direction){
        case PANDA_NET_RX:
        {
#ifdef TAINTDEBUG
            printf("RX packet\n");
            printf("Buf: 0x%lx, Old Buf: 0x%lx, Size %d\n",
                (uint64_t)buf, old_buf_addr, size);
#endif
            if (taint_label_incoming_network_traffic){
                if (!taintEnabled){
                    printf("Taint plugin: Label operation detected (network)\n");
                    printf("Enabling taint processing\n");
                    __taint_enable_taint();
                }
                
                add_taint_io(env, shadow, tob_io_thread, old_buf_addr, size);
                count += size;
                break;
            }
        }
        case PANDA_NET_TX:
#ifdef TAINTDEBUG
            printf("TX packet\n");
            printf("Buf: 0x%lx, Old Buf: 0x%lx, Size %d\n",
                (uint64_t)buf, old_buf_addr, size);
#endif
            if (taintEnabled && taint_query_outgoing_network_traffic){
                TaintOp top;
                top.typ = QUERYOP;
                top.val.query.l = size;
                top.val.query.a = make_iaddr(old_buf_addr);
                // make the taint op buffer bigger if necessary
                tob_resize(&tob_io_thread);
                tob_op_write(tob_io_thread, &top);
            }
            break;
        default:
            assert(0);
    }
    return 0;
}

// this is for much of the network taint transfers.
// this gets called from rr_log.c, rr_replay_skipped_calls, RR_CALL_NET_TRANSFER
// case.
int cb_replay_net_transfer_taint(CPUState *env, uint32_t type, uint64_t src_addr,
        uint64_t dest_addr, uint32_t num_bytes){
    // Replay network transfer as taint transfer
    if (taintEnabled) {
        TaintOp top;
        top.typ = BULKCOPYOP;
        top.val.bulkcopy.l = num_bytes;
        switch (type) {
            case NET_TRANSFER_RAM_TO_IOB:
#ifdef TAINTDEBUG
                printf("NET_TRANSFER_RAM_TO_IOB src: 0x%lx, dest 0x%lx, len %d\n",
                    src_addr, dest_addr, num_bytes);
#endif
                top.val.bulkcopy.a = make_maddr(src_addr);
                top.val.bulkcopy.b = make_iaddr(dest_addr);
                break;
            case NET_TRANSFER_IOB_TO_RAM:
#ifdef TAINTDEBUG
                printf("NET_TRANSFER_IOB_TO_RAM src: 0x%lx, dest 0x%lx, len %d\n",
                    src_addr, dest_addr, num_bytes);
#endif
                top.val.bulkcopy.a = make_iaddr(src_addr);
                top.val.bulkcopy.b = make_maddr(dest_addr);
                break;
            case NET_TRANSFER_IOB_TO_IOB:
#ifdef TAINTDEBUG
                printf("NET_TRANSFER_IOB_TO_IOB src: 0x%lx, dest 0x%lx, len %d\n",
                    src_addr, dest_addr, num_bytes);
#endif
                top.val.bulkcopy.a = make_iaddr(src_addr);
                top.val.bulkcopy.b = make_iaddr(dest_addr);
                break;
            default:
                assert(0);
        }
        // make the taint op buffer bigger if necessary
        tob_resize(&tob_io_thread);
        // add bulk copy corresponding to this hd transfer to buffer
        // of taint ops for io thread.
        tob_op_write(tob_io_thread, &top);
    }
    return 0;
}

// this does a bunch of the dmas in hd taint transfer
int cb_replay_cpu_physical_mem_rw_ram(CPUState *env, uint32_t is_write,
        uint8_t *src_addr, uint64_t dest_addr, uint32_t num_bytes){
    // NB:
    // is_write == 1 means write from qemu buffer to guest RAM.
    // is_write == 0 means RAM -> qemu buffer
    // Replay dmas in hd taint transfer
    if (taintEnabled) {
        TaintOp top;
        top.typ = BULKCOPYOP;
        top.val.bulkcopy.l = num_bytes;
        if (is_write) {
           // its a "write", i.e., transfer from IO buffer to RAM
	    //            printf("cpu_physical_mem_rw IO->RAM\n");
            top.val.bulkcopy.a = make_iaddr((uint64_t)src_addr);
            top.val.bulkcopy.b = make_maddr(dest_addr);
        }
        else {
            // its a "read", i.e., transfer from RAM to IO buffer
	    //            printf("cpu_physical_mem_rw RAM->IO\n");
            top.val.bulkcopy.a = make_maddr(dest_addr);
            top.val.bulkcopy.b = make_iaddr((uint64_t)src_addr);
        }
        // make the taint op buffer bigger if necessary
        tob_resize(&tob_io_thread);
        // add bulk copy corresponding to this hd transfer to buffer
        // of taint ops for io thread.
        tob_op_write(tob_io_thread, &top);
    }
    return 0;
}
#endif


int cb_cpu_restore_state(CPUState *env, TranslationBlock *tb){

    if (taintEnabled){
        //printf("EXCEPTION - logging\n");
        DynValBuffer *dynval_buffer = PIFP->PIV->getDynvalBuffer();
        log_exception(dynval_buffer);

        // Then execute taint ops up until the exception occurs.  Execution of taint
        // ops will stop at the point of the exception.
        rewind_dynval_buffer(dynval_buffer);
        execute_taint_ops(PTFP->ttb, shadow, dynval_buffer);

        // Make sure there's nothing left in the buffer
	assert(dynval_buffer->ptr - dynval_buffer->start == dynval_buffer->cur_size);
    }

    return 0;
}
*/
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
            printf("Taint plugin: Label operation detected\n");
            printf("Enabling taint processing\n");
            __taint_enable_taint();
        }

        // FIXME: do labeling here.
    }

    else if (env->regs[0] == 9){ //Query taint on label
        if (taintEnabled){
            printf("Taint plugin: Query operation detected\n");
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

#ifdef TARGET_I386
// XXX: Support all features of label and query program
void i386_hypercall_callback(CPUState *env){
    //target_ulong buf_start = env->regs[R_EBX];
    //target_ulong buf_len = env->regs[R_ECX];

    // call to iferret to label data
    // EBX contains addr of that data
    // ECX contains size of data
    // EDI is a pointer to a buffer containing the label string
    // ESI contains the length of that label
    // EDX = starting offset (for positional labels only)

    if (env->regs[R_EAX] == 7 || env->regs[R_EAX] == 8){
        if (!taintEnabled){
            printf("Taint plugin: Label operation detected\n");
            printf("Enabling taint processing\n");
	    __taint_enable_taint();
        }
        // FIXME: Add taint.
    }    

    //mz Query taint on this buffer
    //mz EBX = start of buffer (VA)
    //mz ECX = size of buffer (bytes)
    // EDI is a pointer to a buffer containing the filename or another name for this query
    // ESI contains the length of that string
    // EDX = starting offset - for file queries
    else if (env->regs[R_EAX] == 9){ //Query taint on label
        if (taintEnabled){
            printf("Taint plugin: Query operation detected\n");
            //bufplot(env, shadow, &a, (int)buf_len);
        }
        //printf("Disabling taint processing\n");
        //taintEnabled = false;
        //taintJustDisabled = true;
        //printf("Label occurrences on HD: %d\n", shad_dir_occ_64(shadow->hd));
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

/*
// label this phys addr in memory with this label 
void __taint_label_ram(uint64_t pa, uint32_t l) {
    tp_label_ram(shadow, pa, l);
}

static int put_int(uint32_t val, void *place) {
  *(uint32_t *)place = val;
  return 0;
}

uint32_t __taint_pick_label(uint64_t pa) {
  uint32_t result = ~0;
  tp_ls_ram_iter(shadow, pa, put_int, &result);
  return result;
}

// if phys addr pa is untainted, return 0.
// else returns label set cardinality 
uint32_t __taint_query_ram(uint64_t pa) {
  return (tp_query_ram(shadow, pa));
}


uint32_t __taint_query_reg(int reg_num, int offset) {
  return tp_query_reg(shadow, reg_num, offset);
}


void __taint_delete_ram(uint64_t pa) {
  tp_delete_ram(shadow, pa);
}


void taint_labels_ram_iter(uint64_t pa, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
  tp_ls_ram_iter(shadow, pa, app, stuff2);
}


void taint_labels_reg_iter(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
  tp_ls_reg_iter(shadow, reg_num, offset, app, stuff2);
}



uint32_t __taint_occ_ram() {
  return tp_occ_ram(shadow);
}


uint32_t __taint_max_obs_ls_type(void) {
    return shadow->max_obs_ls_type;
}

void __taint_clear_tainted_computation_happened(void) {
    shadow->tainted_computation_happened = 0;
}

int __taint_tainted_computation_happened(void) {
    return shadow->tainted_computation_happened;
}


void __taint_clear_taint_state_changed(void) {
    shadow->taint_state_changed = 0;
}

int __taint_taint_state_changed(void) {
    return shadow->taint_state_changed;
}

void __taint_clear_taint_state_read(void) {
    shadow->taint_state_read = 0;
}
int __taint_taint_state_read(void) {
    return shadow->taint_state_read;
}
void __taint_clear_shadow_memory(void){
    clear_shadow_memory(&shadow);
}


////////////////////////////////////////////////////////////////////////////////////
// C API versions


void taint_enable_taint(void) {
  __taint_enable_taint();
}

int taint_enabled(void) {
  return __taint_enabled();
}

void taint_label_ram(uint64_t pa, uint32_t l) {
    __taint_label_ram(pa, l);
}

uint32_t taint_pick_label(uint64_t pa) {
  return __taint_pick_label(pa);
}

uint32_t taint_query_ram(uint64_t pa) {
  return __taint_query_ram(pa);
}

void taint_delete_ram(uint64_t pa) {
  __taint_delete_ram(pa);
}

uint32_t taint_query_reg(int reg_num, int offset) {
  return __taint_query_reg(reg_num, offset);
}


uint32_t taint_occ_ram(void) {
  return __taint_occ_ram();
}

uint32_t taint_max_obs_ls_type(void) {
    return __taint_max_obs_ls_type();
}


void taint_clear_tainted_computation_happened(void) {
    __taint_clear_tainted_computation_happened();
}

int taint_tainted_computation_happened(void) {
    return __taint_tainted_computation_happened();
}

void taint_clear_taint_state_changed(void) {
    __taint_clear_taint_state_changed();
}

int taint_taint_state_changed(void) {
    return __taint_taint_state_changed();
}

void taint_clear_taint_state_read(void) {
    __taint_clear_taint_state_read();
}

int taint_taint_state_read(void) {
    return __taint_taint_state_read();
}

void taint_clear_shadow_memory(void){
    __taint_clear_shadow_memory();
}
*/

////////////////////////////////////////////////////////////////////////////////////
bool before_block_exec_invalidate_opt(CPUState *env, TranslationBlock *tb) {
    __taint_enable_taint();
    if (!tb->llvm_tc_ptr) {
        return false;
    } else {
        return true;
    }
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

    return true;
}





int print_labels (uint32_t el, void *stuff) { 
  if (stuff == NULL) {
    printf ("%d ", el); 
  }
  else {
    FILE *fp = (FILE *) stuff;
    fprintf (fp, "%d ", el);
  }
  return 0;
}


void uninit_plugin(void *self) {

    printf ("uninit taint plugin\n");
    
    if (taintfpm) delete taintfpm; // Delete function pass manager and pass
    if (shadow) tp_free(shadow);

    panda_disable_llvm();
    panda_disable_memcb();
    panda_enable_tb_chaining();

}




