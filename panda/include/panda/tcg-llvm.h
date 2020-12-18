/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Currently maintained by:
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *
 * All contributors are listed in S2E-AUTHORS file.
 *
 */
#pragma once

// Compatibility layer for struct/class declarations.
// Makes header compatible with both C/C++. Hushes clang's warnings.
// P.S.: It ain't stupid if it works.
#if defined(__cplusplus)
#define __class_compat_var
#define __class_compat_decl(_name) \
class _name;
#else
#define __class_compat_var struct
#define __class_compat_decl(_name) \
struct _name; \
typedef struct _name _name;
#endif

#if defined(__cplusplus)
extern "C" {
#endif
#include <stdint.h>

// Definition from QEMU 1.0.1
#define TCG_MAX_LABELS 512

/*****************************/
/* Functions for QEMU c code */

/* defined in include/exec/exec-all.h */
struct TranslationBlock;

/* defined in tcg/tcg.h */
struct TCGContext;

/* defined in include/panda/tcg-llvm.h (here) */
__class_compat_decl(TCGLLVMTranslator)
struct TCGLLVMRuntime;

/* defined in panda/llvm/tcg-llvm.cpp */
extern __class_compat_var TCGLLVMTranslator *tcg_llvm_translator;
extern __class_compat_var TCGLLVMRuntime tcg_llvm_runtime;

/* defined in vl.c */
void tcg_llvm_initialize(void);
void tcg_llvm_destroy(void);

/* defined in panda/llvm/tcg-llvm.cpp */
void tcg_llvm_tb_alloc(struct TranslationBlock *tb);
void tcg_llvm_tb_free(struct TranslationBlock *tb);
const char* tcg_llvm_get_func_name(struct TranslationBlock *tb);
void tcg_llvm_gen_code(__class_compat_var TCGLLVMTranslator *l,
    struct TCGContext *s, struct TranslationBlock *tb);
uintptr_t tcg_llvm_qemu_tb_exec(CPUArchState *env,
    struct TranslationBlock *tb);
void tcg_llvm_write_module(__class_compat_var TCGLLVMTranslator *l,
    const char *path);
uintptr_t tcg_llvm_get_module_ptr(TCGLLVMTranslator *l);

struct TCGLLVMRuntime {
    // NOTE: The order of these are fixed !
    uint64_t helper_ret_addr;
    uint64_t helper_call_addr;
    uint64_t helper_regs[3];
    // END of fixed block
    struct TranslationBlock* last_tb;
};

#if defined(__cplusplus)
}
#endif

#if defined(__cplusplus)

extern "C++" {

#include <memory>
#include <unordered_map>

/***********************************/
/* External interface for C++ code */

#include <llvm/ExecutionEngine/Orc/ThreadSafeModule.h>
#include <llvm/ExecutionEngine/Orc/LLJIT.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/Threading.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Scalar/GVN.h>

using NewModuleCallback = std::function<void(llvm::Module *module,
    llvm::legacy::FunctionPassManager *functionPassManager)>;

class TCGLLVMTranslator {
    private:
    // List of functions to call when a new module is created
    std::vector<NewModuleCallback> newModuleCallbacks;
    std::map<std::pair<int64_t, llvm::Type *>, llvm::Value *>
        m_envOffsetValues;
    llvm::orc::ThreadSafeContext m_tsc = llvm::orc::ThreadSafeContext(
        std::move(std::make_unique<llvm::LLVMContext>()));
    llvm::LLVMContext *m_context = m_tsc.getContext();
    llvm::IRBuilder<> m_builder;
    std::unique_ptr<llvm::Module> m_module =
        std::make_unique<llvm::Module>("tcg-llvm", *m_context);
    std::string m_CPUArchStateName;
    llvm::Value *m_envInt;
    llvm::StructType *m_CPUArchStateType = nullptr;
    llvm::ExitOnError ExitOnErr;

    llvm::orc::JITTargetMachineBuilder JTMB =
        ExitOnErr(llvm::orc::JITTargetMachineBuilder::detectHost());

    std::unique_ptr<llvm::orc::LLLazyJIT> jit =
        ExitOnErr(llvm::orc::LLLazyJITBuilder().
            setJITTargetMachineBuilder(JTMB).
            create());

    llvm::DataLayout DL = jit->getDataLayout();

    void delLabel(int idx);

    llvm::Value* getEnvOffsetPtr(int64_t offset, TCGTemp &temp);

    /* Function pass manager (used for optimizing the code) */
    llvm::legacy::FunctionPassManager *m_functionPassManager;

    /* Count of generated translation blocks */
    int m_tbCount;

    /* XXX: The following members are "local" to generateCode method */

    /* TCGContext for current translation block */
    TCGContext* m_tcgContext;

    TranslationBlock *m_tb;

    /* Function for current translation block */
    llvm::Function *m_tbFunction;

    /* Current temp m_values */
    llvm::Value* m_values[TCG_MAX_TEMPS];

    /* Pointers to in-memory versions of globals or local temps */
    llvm::Value* m_memValuesPtr[TCG_MAX_TEMPS];

    /* For reg-based globals, store argument number,
     * for mem-based globals, store base value index */
    int m_globalsIdx[TCG_MAX_TEMPS];

    //std::unordered_map<TCGLabel *, llvm::BasicBlock *> m_labels;
    llvm::BasicBlock *m_labels[TCG_MAX_LABELS];

    llvm::FunctionType *m_tbType;
    llvm::Type *m_cpuType;
    llvm::Value *m_cpuState;

    // Represents CPU state pointer cast to an int
    llvm::Instruction *m_cpuStateInt;

    // This instruction is a no-op in the entry block, we use it
    // in order to simplify instruction insertion.
    llvm::Instruction *m_noop;
    llvm::Value *m_eip;
    llvm::Value *m_ccop;

    llvm::Value *getEnv();

    void checkAndLogLLVMIR();

    void initMemoryHelpers();

    /* Shortcuts */
    llvm::Type *intType(int w) {
        return llvm::IntegerType::get(*m_context, w);
    }
    llvm::Type *intPtrType(int w) {
        return llvm::PointerType::get(intType(w), 0);
    }
    llvm::Type *wordType() {
        return intType(TCG_TARGET_REG_BITS);
    }
    llvm::Type *wordPtrType() {
        return intPtrType(TCG_TARGET_REG_BITS);
    }
    llvm::FunctionType *tbType();

    llvm::Constant* constInt(int bits, uint64_t value) {
        return llvm::ConstantInt::get(intType(bits), value);
    }

    llvm::Constant* constWord(uint64_t value) {
        return llvm::ConstantInt::get(wordType(), value);
    }

    void adjustTypeSize(unsigned target, llvm::Value **v1);

    llvm::Value *generateCpuStatePtr(uint64_t arg, unsigned sizeInBytes);

    void generateQemuCpuLoad(const TCGArg *args, unsigned memBits,
        unsigned regBits, bool signExtend);

    void generateQemuCpuStore(const TCGArg *args, unsigned memBits,
        llvm::Value *valueToStore);

    void adjustTypeSize(unsigned target, llvm::Value **v1, llvm::Value **v2) {
        adjustTypeSize(target, v1);
        adjustTypeSize(target, v2);
    }

    llvm::Type* tcgType(int type) {
        return type == TCG_TYPE_I64 ? intType(64) : intType(32);
    }

    llvm::Type* tcgPtrType(int type) {
        return type == TCG_TYPE_I64 ? intPtrType(64) : intPtrType(32);
    }

    llvm::Value* getValue(int idx);
    void setValue(int idx, llvm::Value *v);
    void delValue(int idx);

    llvm::Value *getPtrForValue(int idx);
    void delPtrForValue(int idx);
    void initGlobalsAndLocalTemps();
    void loadNativeCpuState(llvm::Function *f);
    unsigned getValueBits(int idx);

    void invalidateCachedMemory();

    llvm::BasicBlock* getLabel(int idx);
    void startNewBasicBlock(llvm::BasicBlock *bb = nullptr);

    llvm::Value *generateQemuMemOp(bool ld, llvm::Value *value,
        llvm::Value *addr, int flags, int mem_index, int bits,
        uintptr_t ret_addr);

    int generateOperation(int opc, const TCGOp *op, const TCGArg *args);

    void jitPendingModule();

    public:
    TCGLLVMTranslator();
    ~TCGLLVMTranslator();

    llvm::orc::LLLazyJIT *getJit() const {
        return &*jit;
    }

    llvm::orc::ExecutionSession &getExecutionSession() const {
        return jit->getExecutionSession();
    }

    llvm::LLVMContext *getContext() const {
        return m_context;
    }

    llvm::Module *getModule() const {
        return m_module.get();
    }

    llvm::legacy::FunctionPassManager* getFunctionPassManager() const {
        return m_functionPassManager;
    }

    /* Code generation */
    void generateCode(TCGContext *s, TranslationBlock *tb);

    void writeModule(const char* path);

    void addNewModuleCallback(NewModuleCallback newModuleCallback) {
        newModuleCallbacks.push_back(newModuleCallback);
    }

    llvm::DataLayout *getDataLayout() {
        return &DL;
    }
};

}
#endif

#undef __class_compat_decl
#undef __class_compat_var
