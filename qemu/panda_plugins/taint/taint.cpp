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

#include "qemu-common.h"
#include "cpu-all.h"
#ifndef CONFIG_SOFTMMU
#include "syscall_defs.h"
#endif



#include <sys/time.h>
#include "panda_plugin.h"
#include "panda/network.h"
#ifdef CONFIG_SOFTMMU
#include "rr_log.h"
#endif

    extern int compute_is_delete;
    extern int loglevel;
    
    // For the C API to taint accessible from other plugins
    void taint_enable_taint(void);
    int taint_enabled(void);
    void taint_label_ram(uint64_t pa, uint32_t l) ;
    uint32_t taint_query_ram(uint64_t pa);
    uint32_t taint_pick_label(uint64_t pa);
    uint32_t taint_query_reg(int reg_num, int offset);
    uint32_t taint_query_llvm(int reg_num, int offset);
    void taint_spit_reg(int reg_num, int offset);
    void taint_spit_llvm(int reg_num, int offset);
    void taint_delete_ram(uint64_t pa) ;
    uint32_t taint_occ_ram(void) ;
    uint32_t taint_get_ls_type_llvm(int reg_num, int offset);
    uint32_t taint_max_obs_ls_type(void) ;
    void taint_clear_tainted_computation_happened(void) ;
    int taint_tainted_computation_happened(void) ;
    void taint_clear_taint_state_changed(void);
    int taint_taint_state_changed(void);
    void taint_clear_taint_state_read(void);
    int taint_taint_state_read(void);
    void taint_clear_shadow_memory(void);

}

#include "llvm/PassManager.h"
#include "llvm/PassRegistry.h"
#include "llvm/Analysis/Verifier.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"

#include "tcg-llvm.h"

#include "panda_stats.h"
#include "panda_memlog.h"
#include "panda_common.h"

#include "llvm_taint_lib.h"
#include "panda_dynval_inst.h"
#include "taint_processor.h"


// defined in panda/taint_processor.c
extern uint32_t max_taintset_card;
extern uint32_t max_taintset_compute_number;
// Label all incoming network traffic as tainted
extern bool taint_label_incoming_network_traffic;
// Query all outgoing network traffic for taint
extern bool taint_query_outgoing_network_traffic;
// this is on by default
extern int tainted_pointer;
// default is byte labeling
extern int taint_label_mode;
// Global number of taint labels
extern int count;

extern int tainted_instructions;

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {


bool init_plugin(void *);
void uninit_plugin(void *);
int before_block_exec(CPUState *env, TranslationBlock *tb);
int after_block_exec(CPUState *env, TranslationBlock *tb,
    TranslationBlock *next_tb);
int cb_cpu_restore_state(CPUState *env, TranslationBlock *tb);
int guest_hypercall_callback(CPUState *env);

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

#ifndef CONFIG_SOFTMMU
int user_after_syscall(void *cpu_env, bitmask_transtbl *fcntl_flags_tbl,
                       int num, abi_long arg1, abi_long arg2, abi_long arg3,
                       abi_long arg4, abi_long arg5, abi_long arg6, abi_long
                       arg7, abi_long arg8, void *p, abi_long ret);

#endif
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

// Taint and instrumentation function passes
llvm::PandaTaintFunctionPass *PTFP = NULL;
llvm::PandaInstrFunctionPass *PIFP = NULL;

// For now, taint becomes enabled when a label operation first occurs, and
// becomes disabled when a query operation subsequently occurs
bool taintEnabled = false;

// Lets us know right when taint was enabled
bool taintJustEnabled = false;

// Lets us know right when taint was disabled
bool taintJustDisabled = false;


// Globals needed for taint io buffer
TaintOpBuffer *tob_io_thread;
uint32_t       tob_io_thread_max_size = 1024 * 1024;


// returns 1 iff taint is on
int __taint_enabled() {
  if (taintEnabled == true) {
    return 1;
  }
  return 0;
}

/*
 * These memory callbacks are only for whole-system mode.  User-mode memory
 * accesses are captured by IR instrumentation.
 */
int phys_mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    DynValBuffer *dynval_buffer = PIFP->PIV->getDynvalBuffer();
    log_dynval(dynval_buffer, ADDRENTRY, STORE, addr);
    return 0;
}

int phys_mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr,
        target_ulong size, void *buf){
    DynValBuffer *dynval_buffer = PIFP->PIV->getDynvalBuffer();
    log_dynval(dynval_buffer, ADDRENTRY, LOAD, addr);
    return 0;
}

namespace llvm {

static void llvm_init(){
    ExecutionEngine *ee = tcg_llvm_ctx->getExecutionEngine();
    FunctionPassManager *fpm = tcg_llvm_ctx->getFunctionPassManager();
    Module *mod = tcg_llvm_ctx->getModule();
    LLVMContext &ctx = mod->getContext();

    // Link logging function in with JIT
    Function *logFunc;
    std::vector<Type*> argTypes;
    // DynValBuffer*
    argTypes.push_back(IntegerType::get(ctx, 8*sizeof(uintptr_t)));
    // DynValEntryType
    argTypes.push_back(IntegerType::get(ctx, 8*sizeof(DynValEntryType)));
    // LogOp
    argTypes.push_back(IntegerType::get(ctx, 8*sizeof(LogOp)));
    // Dynamic value
    argTypes.push_back(IntegerType::get(ctx, 8*sizeof(uintptr_t)));
    logFunc = Function::Create(
            FunctionType::get(Type::getVoidTy(ctx), argTypes, false),
            Function::ExternalLinkage, "log_dynval", mod);
    logFunc->addFnAttr(Attribute::AlwaysInline);
    ee->addGlobalMapping(logFunc, (void*) &log_dynval);

    // Create instrumentation pass and add to function pass manager
    llvm::FunctionPass *instfp = createPandaInstrFunctionPass(mod);
    fpm->add(instfp);
    PIFP = static_cast<PandaInstrFunctionPass*>(instfp);
}

} // namespace llvm



void __taint_enable_taint(void) {
    if(taintEnabled) {return;}
  printf ("__taint_enable_taint\n");
  taintJustEnabled = true;
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
    pcb.cb_cpu_restore_state = cb_cpu_restore_state;
    panda_register_callback(plugin_ptr, PANDA_CB_CPU_RESTORE_STATE, pcb);

    // for hd and network taint
#ifdef CONFIG_SOFTMMU
    pcb.replay_hd_transfer = cb_replay_hd_transfer_taint;
    panda_register_callback(plugin_ptr, PANDA_CB_REPLAY_HD_TRANSFER, pcb);
    pcb.replay_net_transfer = cb_replay_net_transfer_taint;
    panda_register_callback(plugin_ptr, PANDA_CB_REPLAY_NET_TRANSFER, pcb);
    pcb.replay_before_cpu_physical_mem_rw_ram = cb_replay_cpu_physical_mem_rw_ram;
    panda_register_callback(plugin_ptr, PANDA_CB_REPLAY_BEFORE_CPU_PHYSICAL_MEM_RW_RAM, pcb);
#endif

    panda_enable_precise_pc(); //before_block_exec requires precise_pc for panda_current_asid

    if (!execute_llvm){
        panda_enable_llvm();
    }
    llvm::llvm_init();
    panda_enable_llvm_helpers();

    /*
     * Run instrumentation pass over all helper functions that are now in the
     * module, and verify module.
     */
    llvm::Module *mod = tcg_llvm_ctx->getModule();
    for (llvm::Module::iterator i = mod->begin(); i != mod->end(); i++){
        if (i->isDeclaration()){
            continue;
        }
#if defined(TARGET_ARM)
        //TODO: Fix handling of ARM's cpu_reset() helper
        // Currently, we skip instrumenting it, because we generate invalid LLVM bitcode if we try
        std::string modname =  i->getName().str();
        if (modname == "cpu_reset_llvm"){
            printf("Skipping instrumentation of cpu_reset\n");
            continue;
        }
#endif
        PIFP->runOnFunction(*i);
    }
    std::string err;
    if(verifyModule(*mod, llvm::AbortProcessAction, &err)){
        printf("%s\n", err.c_str());
        exit(1);
    }

    /*
     * Taint processor initialization
     */

    //uint32_t ram_size = 536870912; // 500MB each
#ifdef TARGET_X86_64
    // this is only for the fast bitmap which we currently aren't using for
    // 64-bit, it only supports 32-bit
    //XXX FIXME
    uint64_t ram_size = 0;
#else
    uint32_t ram_size = 0xffffffff; //guest address space -- QEMU user mode
#endif
    uint64_t hd_size =  536870912;
    uint64_t io_size = 536870912;
    uint16_t num_vals = 2000; // LLVM virtual registers //XXX assert this
    shadow = tp_init(hd_size, ram_size, io_size, num_vals);
    if (shadow == NULL){
        printf("Error initializing shadow memory...\n");
        exit(1);
    }

    taintfpm = new llvm::FunctionPassManager(tcg_llvm_ctx->getModule());

    // Add the taint analysis pass to our taint pass manager
    llvm::FunctionPass *taintfp =
        llvm::createPandaTaintFunctionPass(15*1048576/* global taint op buffer
        size, 10MB */, NULL /* existing taint cache */);
    PTFP = static_cast<llvm::PandaTaintFunctionPass*>(taintfp);
    taintfpm->add(taintfp);
    taintfpm->doInitialization();

    // Populate taint cache with helper function taint ops
    for (llvm::Module::iterator i = mod->begin(); i != mod->end(); i++){
        if (i->isDeclaration()){
            continue;
        }
        PTFP->runOnFunction(*i);
    }
}




// Derive taint ops
int before_block_exec(CPUState *env, TranslationBlock *tb){

    shadow->asid = panda_current_asid(env);

    //printf("%s\n", tcg_llvm_get_func_name(tb));

    if (taintEnabled){
        // process taint ops in io thread taint op buffer
        // NB: we don't need a dynval buffer here.
        tob_process(tob_io_thread, shadow, NULL);
        tob_clear(tob_io_thread);

        taintfpm->run(*(tb->llvm_function));
        DynValBuffer *dynval_buffer = PIFP->PIV->getDynvalBuffer();
        clear_dynval_buffer(dynval_buffer);
    }

    return 0;
}

// Execute taint ops
int after_block_exec(CPUState *env, TranslationBlock *tb,
        TranslationBlock *next_tb){

    if (taintJustEnabled){
        // need to wait until the next TB to start executing taint ops
        taintJustEnabled = false;
	//	mytimer_start(ttimer);
        return 0;
    }
    if (taintJustDisabled){
        taintJustDisabled = false;
        execute_llvm = 0;
        generate_llvm = 0;
        panda_do_flush_tb();
        panda_disable_memcb();
	//	mytimer_start(ttimer);
        return 0;
    }

    if (taintEnabled){
        DynValBuffer *dynval_buffer = PIFP->PIV->getDynvalBuffer();
        rewind_dynval_buffer(dynval_buffer);

        //printf("%s\n", tb->llvm_function->getName().str().c_str());
        //PTFP->debugTaintOps();
        //printf("\n\n");

        execute_taint_ops(PTFP->ttb, shadow, dynval_buffer);

        // Make sure there's nothing left in the buffer
	assert(dynval_buffer->ptr - dynval_buffer->start == dynval_buffer->cur_size);

    }

    return 0;
}

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

#ifdef TARGET_ARM
// R0 is command (label or query)
// R1 is buf_start
// R2 is length
// R3 is offset (not currently implemented)
void arm_hypercall_callback(CPUState *env){
    target_ulong buf_start = env->regs[1];
    target_ulong buf_len = env->regs[2];

    if (env->regs[0] == 7 || env->regs[0] == 8){ //Taint label
        if (!taintEnabled){
            printf("Taint plugin: Label operation detected\n");
            printf("Enabling taint processing\n");
            __taint_enable_taint();
        }

        TaintOpBuffer *tempBuf = tob_new(buf_len * sizeof(TaintOp));
        add_taint_ram(env, shadow, tempBuf, (uint64_t)buf_start, (int)buf_len);
        tob_delete(tempBuf);
    }

    else if (env->regs[0] == 9){ //Query taint on label
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
}
#endif //TARGET_ARM

#ifdef TARGET_I386
// XXX: Support all features of label and query program
void i386_hypercall_callback(CPUState *env){
    target_ulong buf_start = env->regs[R_EBX];
    target_ulong buf_len = env->regs[R_ECX];

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
        TaintOpBuffer *tempBuf = tob_new( buf_len * sizeof(TaintOp));
	add_taint_ram(env, shadow, tempBuf, (uint64_t)buf_start, (int)buf_len);
        tob_delete(tempBuf);
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
            Addr a = make_maddr(buf_start);
            bufplot(env, shadow, &a, (int)buf_len);
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

#ifndef CONFIG_SOFTMMU

// Globals to keep track of file descriptors
int infd = -1;
int outfd = -1;

/*
 * Kind of a hacky way to see if the file being opened is something we're
 * interested in.  For now, we are working under the assumption that a program
 * will open/read one file of interest, and open/write the other file of
 * interest.  So we assume that files that are opened from /etc and /lib aren't
 * of interest. /proc and openssl.cnf also aren't interesting, from looking at
 * openssl.
 */
static int user_open(bitmask_transtbl *fcntl_flags_tbl, abi_long ret, void *p,
              abi_long flagarg){
    const char *file = path((const char*)p);
    unsigned int flags = target_to_host_bitmask(flagarg, fcntl_flags_tbl);
    if (ret > 0){
        if((strncmp(file, "/etc", 4) != 0)
                && (strncmp(file, "/lib", 4) != 0)
                && (strncmp(file, "/proc", 5) != 0)
                //&& (strncmp(file, "/dev", 4) != 0)
                && (strncmp(file, "/usr", 4) != 0)
                && (strstr(file, "openssl.cnf") == 0)
                && (strstr(file, "xpdfrc") == 0)){
            printf("open %s for ", file);
            if ((flags & (O_RDONLY | O_WRONLY)) == O_RDONLY){
                printf("read\n");
                infd = ret;
            }
            if (flags & O_WRONLY){
                printf("write\n");
                outfd = ret;
            }
        }
    }
    return 0;
}

static int user_creat(abi_long ret, void *p){
    const char *file = path((const char*)p);
    if (ret > 0){
        printf("open %s for write\n", file);
        outfd = ret;
    }
    return 0;
}

static int user_read(CPUState *env, abi_long ret, abi_long fd, void *p){
    if (ret > 0 && fd == infd){
        TaintOpBuffer *tempBuf = tob_new(5*1048576 /* 1MB */);
        add_taint_ram(env, shadow, tempBuf, (uint64_t)p /*pointer*/, ret /*length*/);
        tob_delete(tempBuf);
    }
    return 0;
}

static int user_write(CPUState *env, abi_long ret, abi_long fd, void *p){
    if (ret > 0 && fd == outfd){
        Addr a = make_maddr((uint64_t)p);
        bufplot(env, shadow, &a /*pointer*/, ret /*length*/);
    }
    return 0;
}

int user_after_syscall(void *cpu_env, bitmask_transtbl *fcntl_flags_tbl,
                       int num, abi_long arg1, abi_long arg2, abi_long arg3,
                       abi_long arg4, abi_long arg5, abi_long arg6,
                       abi_long arg7, abi_long arg8, void *p, abi_long ret){
    CPUState *env = (CPUState *)cpu_env;
    switch (num){
        case TARGET_NR_read:
            user_read(env, ret, arg1, p);
            break;
        case TARGET_NR_write:
            user_write(env, ret, arg1, p);
            break;
        case TARGET_NR_open:
            user_open(fcntl_flags_tbl, ret, p, arg2);
            break;
        case TARGET_NR_openat:
            user_open(fcntl_flags_tbl, ret, p, arg3);
            break;
        case TARGET_NR_creat:
            user_creat(ret, p);
            break;
        default:
            break;
    }
    return 0;
}

#endif // CONFIG_SOFTMMU




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

uint32_t __taint_query_llvm(int reg_num, int offset) {
  return tp_query_llvm(shadow, reg_num, offset);
}

void __taint_spit_reg(int reg_num, int offset) {
  tp_spit_reg(shadow, reg_num, offset);
}

void __taint_spit_llvm(int reg_num, int offset) {
  tp_spit_llvm(shadow, reg_num, offset);
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

void taint_labels_llvm_iter(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
  tp_ls_llvm_iter(shadow, reg_num, offset, app, stuff2);
}



uint32_t __taint_occ_ram() {
  return tp_occ_ram(shadow);
}


uint32_t __taint_max_obs_ls_type(void) {
    return shadow->max_obs_ls_type;
}

uint32_t __taint_get_ls_type_llvm(int reg_num, int offset) {
    return tp_get_ls_type_llvm(shadow, reg_num, offset);
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

uint32_t taint_query_llvm(int reg_num, int offset) {
  return __taint_query_llvm(reg_num, offset);
}

void taint_spit_reg(int reg_num, int offset) {
  __taint_spit_reg(reg_num, offset);
}

void taint_spit_llvm(int reg_num, int offset) {
  __taint_spit_llvm(reg_num, offset);
}


uint32_t taint_occ_ram(void) {
  return __taint_occ_ram();
}

uint32_t taint_max_obs_ls_type(void) {
    return __taint_max_obs_ls_type();
}

uint32_t taint_get_ls_type_llvm(int reg_num, int offset) {
    return __taint_get_ls_type_llvm(reg_num, offset);
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


////////////////////////////////////////////////////////////////////////////////////

bool init_plugin(void *self) {
    printf("Initializing taint plugin\n");
    plugin_ptr = self;
    panda_cb pcb;
    panda_enable_memcb();
    panda_disable_tb_chaining();
    pcb.guest_hypercall = guest_hypercall_callback;
    panda_register_callback(self, PANDA_CB_GUEST_HYPERCALL, pcb);
    pcb.replay_handle_packet = handle_packet;
    panda_register_callback(plugin_ptr, PANDA_CB_REPLAY_HANDLE_PACKET, pcb);
#ifndef CONFIG_SOFTMMU
    pcb.user_after_syscall = user_after_syscall;
    panda_register_callback(self, PANDA_CB_USER_AFTER_SYSCALL, pcb);
#endif

    tob_io_thread = tob_new(tob_io_thread_max_size);

    panda_arg_list *args = panda_get_args("taint");
    int i;
    if (NULL != args) {
        for (i = 0; i < args->nargs; i++) {
            if (0 == strncmp(args->list[i].key, "max_taintset_card", 17)) {
                max_taintset_card = atoi(args->list[i].value);
                printf ("max_taintset_card = %d\n", max_taintset_card);
            }
            
            if (0 == strncmp(args->list[i].key, "max_taintset_compute_number", 24)) {
                max_taintset_compute_number = atoi(args->list[i].value);
                printf ("max_taintset_compute_number = %d\n", max_taintset_compute_number);
            }
            
            if (0 == strncmp(args->list[i].key, "compute_is_delete", 17)) {
                compute_is_delete = 1;
            }
            if (0 == strncmp(args->list[i].key, "label_incoming_network", 22)) {
                taint_label_incoming_network_traffic = 1;
            }
            if (0 == strncmp(args->list[i].key, "query_outgoing_network", 22)) {
                taint_query_outgoing_network_traffic = 1;
            }
            if (0 == strncmp(args->list[i].key, "no_tainted_pointer", 18)) {
                tainted_pointer = 0;
            }
            if (0 == strncmp(args->list[i].key, "label_mode", 10)) {
                if (0 == strncmp(args->list[i].value, "binary", 6)){
                    taint_label_mode = TAINT_BINARY_LABEL;
                }
                else if (0 == strncmp(args->list[i].value, "byte", 4)){
                    taint_label_mode = TAINT_BYTE_LABEL;
                }
                else {
                    printf("Invalid taint label_mode.  Using default byte label.\n");
                    taint_label_mode = TAINT_BYTE_LABEL;
                }
            }
            
            if (0 == strncmp (args->list[i].key, "tainted_instructions", 20)) {
                tainted_instructions = 1;
            }
            
        }
    }
    

    if (taint_label_mode == TAINT_BYTE_LABEL){
        printf("Taint: running in byte labeling mode.\n");
    }
    else if (taint_label_mode == TAINT_BINARY_LABEL){
        printf("Taint: running in binary labeling mode.\n");
    }
    printf ("max_taintset_card = %d\n", max_taintset_card);
    printf ("max_taintset_compute_number = %d\n", max_taintset_compute_number);
    printf ("taint_label_incoming_network_traffic = %d\n",
        taint_label_incoming_network_traffic);
    printf ("taint_query_outgoing_network_traffic = %d\n",
        taint_query_outgoing_network_traffic);
    printf ("tainted_pointer = %d\n", tainted_pointer);
    
    printf ("compute_is_delete = %d\n", compute_is_delete);
    printf ("done initializing taint plugin\n");

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
    
    if (tainted_instructions) {
        for ( auto &kvp : shadow->tpc ) {
            uint64_t asid = kvp.first;
            printf ("asid = %lx\n", asid);
            for ( auto &pc : kvp.second ) {
                printf ("instr is tainted :  asid=0x%lx : pc=0x%lx \n", asid, pc);
            }
        }
    }
    
    
    /*
     * XXX: Here, we unload our pass from the PassRegistry.  This seems to work
     * fine, until we reload this plugin again into QEMU and we get an LLVM
     * assertion saying the pass is already registered.  This seems like a bug
     * with LLVM.  Switching between TCG and LLVM works fine when passes aren't
     * added to LLVM.
     */
    llvm::PassRegistry *pr = llvm::PassRegistry::getPassRegistry();
    const llvm::PassInfo *pi =
        //pr->getPassInfo(&llvm::PandaInstrFunctionPass::ID);
        pr->getPassInfo(llvm::StringRef("PandaInstr"));
    if (!pi){
        printf("Unable to find 'PandaInstr' pass in pass registry\n");
    }
    else {
        pr->unregisterPass(*pi);
    }



    if (taintfpm) delete taintfpm; // Delete function pass manager and pass
    if (shadow) tp_free(shadow);
    if (tob_io_thread) tob_delete(tob_io_thread);

    panda_disable_llvm();
    panda_disable_memcb();
    panda_enable_tb_chaining();


}




