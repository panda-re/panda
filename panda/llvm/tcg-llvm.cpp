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

#include <llvm/Support/TargetSelect.h>
#include <llvm/ExecutionEngine/SectionMemoryManager.h>
#include <llvm/ExecutionEngine/JIT.h>

#include <llvm/Bitcode/ReaderWriter.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/PassManager.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/Analysis/Verifier.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/Threading.h>

#include <llvm/Support/DynamicLibrary.h>
#include <llvm/Support/raw_ostream.h>

#include <iostream>
#include <sstream>
#include <map>

#include "panda/cheaders.h"
#include "panda/tcg-llvm.h"
#include "panda/helper_runtime.h"

#if defined(CONFIG_SOFTMMU)

// To support other architectures, make similar minor changes to op_helper.c
static void *qemu_ld_helpers[16];
static void *qemu_st_helpers[16];
static const char *qemu_ld_helper_names[16];
static const char *qemu_st_helper_names[16];

#endif // CONFIG_SOFTMMU

extern "C" {
    TCGLLVMContext *tcg_llvm_ctx = nullptr;

    /* These data is accessible from generated code */
    TCGLLVMRuntime tcg_llvm_runtime = {};
}

extern CPUState *env;

using namespace llvm;

class TJITMemoryManager;

class TCGLLVMContextPrivate {
    LLVMContext& m_context;
    IRBuilder<> m_builder;

    /* Current m_module */
    Module *m_module;

    /* JIT engine */
    TJITMemoryManager *m_jitMemoryManager;
    ExecutionEngine *m_executionEngine;

    /* Function pass manager (used for optimizing the code) */
    FunctionPassManager *m_functionPassManager;

    /* Count of generated translation blocks */
    int m_tbCount;

    /* XXX: The following members are "local" to generateCode method */

    /* TCGContext for current translation block */
    TCGContext* m_tcgContext;

    /* Function for current translation block */
    Function *m_tbFunction;

    /* Current temp m_values */
    Value* m_values[TCG_MAX_TEMPS];

    /* Pointers to in-memory versions of globals or local temps */
    Value* m_memValuesPtr[TCG_MAX_TEMPS];

    std::map<std::pair<int64_t, llvm::Type *>, Value *> m_envOffsetValues;
    Value *m_envInt;

    /* For reg-based globals, store argument number,
     * for mem-based globals, store base value index */
    int m_globalsIdx[TCG_MAX_TEMPS];

    BasicBlock* m_labels[TCG_MAX_LABELS];

    StructType *m_CPUArchStateType = nullptr;
    std::string m_CPUArchStateName;

public:
    TCGLLVMContextPrivate();
    ~TCGLLVMContextPrivate();

    void deleteExecutionEngine() {
        if (m_executionEngine) {
            delete m_executionEngine;
            m_executionEngine = nullptr;
        }
    }

    FunctionPassManager *getFunctionPassManager() const {
        return m_functionPassManager;
    }

    /* Shortcuts */
    llvm::Type* intType(int w) { return IntegerType::get(m_context, w); }
    llvm::Type* intPtrType(int w) { return PointerType::get(intType(w), 0); }
    llvm::Type* wordType() { return intType(TCG_TARGET_REG_BITS); }
    llvm::Type* wordType(int bits) { return intType(bits); }
    llvm::Type* wordPtrType() { return intPtrType(TCG_TARGET_REG_BITS); }

    llvm::Constant* constInt(int bits, uint64_t value) {
        return ConstantInt::get(intType(bits), value);
    }

    void adjustTypeSize(unsigned target, Value **v1) {
        Value *va = *v1;
        if (va->getType() == intType(target)) {
            return;
        } else if (va == m_tbFunction->arg_begin()
                && target == sizeof(uintptr_t) * 8) {
            *v1 = m_envInt;
        } else if (target == 32 && va->getType() == intType(64)) {
            *v1 = m_builder.CreateTrunc(va, intType(target));
        } else {
            assert(false);
        }
    }

    void adjustTypeSize(unsigned target, Value **v1, Value **v2) {
        adjustTypeSize(target, v1);
        adjustTypeSize(target, v2);
    }

    llvm::Type* tcgType(int type) {
        return type == TCG_TYPE_I64 ? intType(64) : intType(32);
    }

    llvm::Type* tcgPtrType(int type) {
        return type == TCG_TYPE_I64 ? intPtrType(64) : intPtrType(32);
    }

    /* Helpers */
    void initMemoryHelpers();
    Value* getValue(int idx);
    void setValue(int idx, Value *v);
    void delValue(int idx);

    Value* getPtrForValue(int idx);
    Value* getEnvOffsetPtr(int64_t offset, TCGTemp &temp);
    void delPtrForValue(int idx);
    void initGlobalsAndLocalTemps();
    unsigned getValueBits(int idx);

    void invalidateCachedMemory();

    uint64_t toInteger(Value *v) const {
        if (ConstantInt *cste = dyn_cast<ConstantInt>(v)) {
            return *cste->getValue().getRawData();
        }
        llvm::errs() << *v << '\n';
        assert(false && "Not a constant");
        return 0; // make clang++ shut up
    }

    BasicBlock* getLabel(int idx);
    void delLabel(int idx);
    void startNewBasicBlock(BasicBlock *bb = nullptr);

    /* Code generation */
    Value* getEnv();
    Value* generateQemuMemOp(bool ld, Value *value, Value *addr, int flags,
                             int mem_index, int bits, uintptr_t ret_addr);
    void generateTraceCall(uintptr_t pc);
    int generateOperation(int opc, const TCGOp *op, const TCGArg *args);
    void generateCode(TCGContext *s, TranslationBlock *tb);

    /* Friends */
    friend class TCGLLVMContext;
};

/* Custom JITMemoryManager in order to capture the size of
 * the last generated function */
class TJITMemoryManager: public SectionMemoryManager {
    JITMemoryManager* m_base;
    std::map<const Function *, ptrdiff_t> m_functionSizes;
public:
    TJITMemoryManager():
        m_base(JITMemoryManager::CreateDefaultMemManager()) {}
    ~TJITMemoryManager() { delete m_base; }

    ptrdiff_t getFunctionSize(const Function *F) const {
        std::map<const Function *, ptrdiff_t>::const_iterator it
            = m_functionSizes.find(F);
        if (it == m_functionSizes.end()) {
            return 0;
        } else {
            return it->second;
        }
    }

    uint8_t *startFunctionBody(const Function *F, uintptr_t &ActualSize) {
        m_functionSizes.erase(F);
        return m_base->startFunctionBody(F, ActualSize);
    }
    void endFunctionBody(const Function *F, uint8_t *FunctionStart,
                                uint8_t *FunctionEnd) {
        m_functionSizes[F] = FunctionEnd - FunctionStart;
        m_base->endFunctionBody(F, FunctionStart, FunctionEnd);
    }

    void setMemoryWritable() { m_base->setMemoryWritable(); }
    void setMemoryExecutable() { m_base->setMemoryExecutable(); }
    void setPoisonMemory(bool poison) { m_base->setPoisonMemory(poison); }
    void AllocateGOT() { m_base->AllocateGOT(); }
    uint8_t *getGOTBase() const { return m_base->getGOTBase(); }
    //void SetDlsymTable(void *ptr) { m_base->SetDlsymTable(ptr); }
    //void *getDlsymTable() const { return m_base->getDlsymTable(); }
    uint8_t *allocateStub(const GlobalValue* F, unsigned StubSize,
                                unsigned Alignment) {
        return m_base->allocateStub(F, StubSize, Alignment);
    }
    uint8_t *allocateSpace(intptr_t Size, unsigned Alignment) {
        return m_base->allocateSpace(Size, Alignment);
    }
    uint8_t *allocateGlobal(uintptr_t Size, unsigned Alignment) {
        return m_base->allocateGlobal(Size, Alignment);
    }
    //void deallocateMemForFunction(const Function *F) {
    //    m_base->deallocateMemForFunction(F);
    //}

    virtual void deallocateFunctionBody(void *Body) {
        m_base->deallocateFunctionBody(Body);
    }

    uint8_t* startExceptionTable(const Function* F, uintptr_t &ActualSize) {
        return m_base->startExceptionTable(F, ActualSize);
    }
    void endExceptionTable(const Function *F, uint8_t *TableStart,
                                 uint8_t *TableEnd, uint8_t* FrameRegister) {
        m_base->endExceptionTable(F, TableStart, TableEnd, FrameRegister);
    }
    virtual void deallocateExceptionTable(void *Body) {
        m_base->deallocateExceptionTable(Body);
    }
    bool CheckInvariants(std::string &ErrorStr) {
        return m_base->CheckInvariants(ErrorStr);
    }
    size_t GetDefaultCodeSlabSize() {
        return m_base->GetDefaultCodeSlabSize();
    }
    size_t GetDefaultDataSlabSize() {
        return m_base->GetDefaultDataSlabSize();
    } size_t GetDefaultStubSlabSize() {
        return m_base->GetDefaultStubSlabSize();
    }
    unsigned GetNumCodeSlabs() { return m_base->GetNumCodeSlabs(); }
    unsigned GetNumDataSlabs() { return m_base->GetNumDataSlabs(); }
    unsigned GetNumStubSlabs() { return m_base->GetNumStubSlabs(); }
};

TCGLLVMContextPrivate::TCGLLVMContextPrivate()
    : m_context(getGlobalContext()), m_builder(m_context), m_tbCount(0),
      m_tcgContext(nullptr), m_tbFunction(nullptr)
{
    std::memset(m_values, 0, sizeof(m_values));
    std::memset(m_memValuesPtr, 0, sizeof(m_memValuesPtr));
    std::memset(m_globalsIdx, 0, sizeof(m_globalsIdx));
    std::memset(m_labels, 0, sizeof(m_labels));

    InitializeNativeTarget();

    initMemoryHelpers();

    m_module = new Module("tcg-llvm", m_context);

    m_jitMemoryManager = new TJITMemoryManager();

    std::string error;

    /* Create JIT with optimization level set to none because some optimizations
     * (I think specifically, one dealing with simplifying CFGs) was messing up
     * our log processing.
     */
    m_executionEngine = ExecutionEngine::createJIT(
            m_module, &error, m_jitMemoryManager, CodeGenOpt::None);
    if(m_executionEngine == nullptr) {
        std::cerr << "Unable to create LLVM JIT: " << error << std::endl;
        exit(1);
    }

    m_functionPassManager = new FunctionPassManager(m_module);
    m_functionPassManager->add(
            new DataLayout(*m_executionEngine->getDataLayout()));

    m_functionPassManager->doInitialization();

#define XSTR(x) STR(x)
#define STR(x) #x
    m_CPUArchStateName = XSTR(CPUArchState);
    m_CPUArchStateName[6] = '.'; // Replace space with dot.
#undef STR
#undef XSTR
}

/* rwhelan: to restart LLVM again, there is either a bug with the
 * FunctionPassManager destructor not unregistering passes, or we need to
 * manually unregister our passes somehow.  If you don't add passes into LLVM,
 * then switching between TCG and LLVM should work fine.
 */
TCGLLVMContextPrivate::~TCGLLVMContextPrivate()
{
    if (m_functionPassManager) {
        delete m_functionPassManager;
        m_functionPassManager = nullptr;
    }

    // the following line will also delete
    // m_moduleProvider, m_module and all its functions
    if (m_executionEngine) {
        delete m_executionEngine;
        m_executionEngine = nullptr;
    }

    if (llvm_is_multithreaded()) {
        llvm_stop_multithreaded();
    }
}

void TCGLLVMContextPrivate::initMemoryHelpers() {
    qemu_ld_helpers[MO_UB] = (void *)helper_ret_ldub_mmu_panda;
    qemu_ld_helpers[MO_LEUW] = (void *)helper_le_lduw_mmu_panda;
    qemu_ld_helpers[MO_LEUL] = (void *)helper_le_ldul_mmu_panda;
    qemu_ld_helpers[MO_LEQ] = (void *)helper_le_ldq_mmu_panda;
    qemu_ld_helpers[MO_BEUW] = (void *)helper_be_lduw_mmu_panda;
    qemu_ld_helpers[MO_BEUL] = (void *)helper_be_ldul_mmu_panda;
    qemu_ld_helpers[MO_BEQ] = (void *)helper_be_ldq_mmu_panda;
    qemu_ld_helper_names[MO_UB] = "helper_ret_ldub_mmu_panda";
    qemu_ld_helper_names[MO_LEUW] = "helper_le_lduw_mmu_panda";
    qemu_ld_helper_names[MO_LEUL] = "helper_le_ldul_mmu_panda";
    qemu_ld_helper_names[MO_LEQ] = "helper_le_ldq_mmu_panda";
    qemu_ld_helper_names[MO_BEUW] = "helper_be_lduw_mmu_panda";
    qemu_ld_helper_names[MO_BEUL] = "helper_be_ldul_mmu_panda";
    qemu_ld_helper_names[MO_BEQ] = "helper_be_ldq_mmu_panda";
    qemu_st_helpers[MO_UB] = (void *)helper_ret_stb_mmu_panda;
    qemu_st_helpers[MO_LEUW] = (void *)helper_le_stw_mmu_panda;
    qemu_st_helpers[MO_LEUL] = (void *)helper_le_stl_mmu_panda;
    qemu_st_helpers[MO_LEQ] = (void *)helper_le_stq_mmu_panda;
    qemu_st_helpers[MO_BEUW] = (void *)helper_be_stw_mmu_panda;
    qemu_st_helpers[MO_BEUL] = (void *)helper_be_stl_mmu_panda;
    qemu_st_helpers[MO_BEQ] = (void *)helper_be_stq_mmu_panda;
    qemu_st_helper_names[MO_UB] = "helper_ret_stb_mmu_panda";
    qemu_st_helper_names[MO_LEUW] = "helper_le_stw_mmu_panda";
    qemu_st_helper_names[MO_LEUL] = "helper_le_stl_mmu_panda";
    qemu_st_helper_names[MO_LEQ] = "helper_le_stq_mmu_panda";
    qemu_st_helper_names[MO_BEUW] = "helper_be_stw_mmu_panda";
    qemu_st_helper_names[MO_BEUL] = "helper_be_stl_mmu_panda";
    qemu_st_helper_names[MO_BEQ] = "helper_be_stq_mmu_panda";
}

Value* TCGLLVMContextPrivate::getPtrForValue(int idx)
{
    TCGContext *s = m_tcgContext;
    TCGTemp &temp = s->temps[idx];

    assert(idx < s->nb_globals || temp.temp_local);

    /* rwhelan: hack to deal with the fact that this code is written assuming
     * 'env' was the 0th index in the array.  This is no longer true, as the
     * '_frame' variable is the 0th index, and 'env' is the 1st index.
     * Generated code will probably not be touching the TCG stack frame, so this
     * should be ok.
     */
    if (temp.name && !strncmp(temp.name, "env", 3)) {
        return m_tbFunction->arg_begin();
    }

    if(m_memValuesPtr[idx] == nullptr) {
        assert(idx < s->nb_globals);

        if(temp.fixed_reg) {
            assert(false);
        } else {
            Value *v = m_builder.CreateAdd(m_envInt, ConstantInt::get(
                        wordType(), temp.mem_offset));
            m_memValuesPtr[idx] = m_builder.CreateIntToPtr(
                    v, tcgPtrType(temp.type),
                    StringRef(temp.name) + "_ptr");
        }
    }

    return m_memValuesPtr[idx];
}

Value* TCGLLVMContextPrivate::getEnvOffsetPtr(int64_t offset, TCGTemp &temp) {
    llvm::Type *tempType = tcgPtrType(temp.type);
    auto key = std::make_pair(offset, tempType);
    auto it = m_envOffsetValues.lower_bound(key);
    // it->first > or = key. > case:
    if (it == m_envOffsetValues.end() || key < it->first) {
        // Have to make sure that these get inserted in a basic block that
        // always runs.
        auto savedIP = m_builder.saveIP();
        BasicBlock *currentBlock = m_builder.GetInsertBlock();
        assert(currentBlock && currentBlock->getParent());
        BasicBlock *entry = &m_tbFunction->front();
        assert(entry);
        if (entry->getTerminator()) {
            // get "false" successor of entry block, i.e. not tcg_exit_req branch.
            BasicBlock *body = entry->getTerminator()->getSuccessor(1);
            assert(body);
            if (currentBlock != entry && currentBlock != body) {
                // this means we are in one of the terminating blocks of the BB.
                // i.e. the halves of a conditional branch.
                if (body->getFirstNonPHI()) {
                    m_builder.SetInsertPoint(body->getFirstNonPHI());
                } else {
                    m_builder.SetInsertPoint(body);
                }
            }
        }

        Value *v = m_builder.CreateAdd(m_envInt, ConstantInt::get(wordType(), offset));
        v = m_builder.CreateIntToPtr(
                v, tcgPtrType(temp.type),
                temp.name ? StringRef(temp.name) + "_ptr": "");
        m_builder.restoreIP(savedIP);
        m_envOffsetValues.insert(it, std::make_pair(key, v));
        return v;
    } else {
        return it->second;
    }
}

static inline void freeValue(Value *V) {
    if(V && V->use_empty() && !isa<Constant>(V)) {
        if(!isa<Instruction>(V) || !cast<Instruction>(V)->getParent())
            delete V;
    }
}

inline void TCGLLVMContextPrivate::delValue(int idx)
{
    freeValue(m_values[idx]);
    m_values[idx] = nullptr;
}

inline void TCGLLVMContextPrivate::delPtrForValue(int idx)
{
    freeValue(m_memValuesPtr[idx]);
    m_memValuesPtr[idx] = nullptr;
}

unsigned TCGLLVMContextPrivate::getValueBits(int idx)
{
    switch (m_tcgContext->temps[idx].type) {
        case TCG_TYPE_I32: return 32;
        case TCG_TYPE_I64: return 64;
        default: assert(false && "Unknown size");
    }
    return 0;
}

Value* TCGLLVMContextPrivate::getValue(int idx)
{
    TCGTemp &temp = m_tcgContext->temps[idx];
    if (temp.name && !strncmp(temp.name, "env", 3)) {
        return m_tbFunction->arg_begin();
    }
    if(m_values[idx] == nullptr) {
        if(idx < m_tcgContext->nb_globals) {
            m_values[idx] = m_builder.CreateLoad(getPtrForValue(idx)
                    , StringRef(temp.name) + "_v"
                    );
        } else if(m_tcgContext->temps[idx].temp_local) {
            m_values[idx] = m_builder.CreateLoad(getPtrForValue(idx));
            std::ostringstream name;
            name << "loc" << (idx - m_tcgContext->nb_globals) << "_v";
            m_values[idx]->setName(name.str());
        } else {
            // Temp value was not previously assigned
            assert(false); // XXX: or return zero constant ?
        }
    }

    return m_values[idx];
}

void TCGLLVMContextPrivate::setValue(int idx, Value *v)
{
    delValue(idx);
    m_values[idx] = v;

    if(!v->hasName() && !isa<Constant>(v)) {
        if(idx < m_tcgContext->nb_globals)
            v->setName(StringRef(m_tcgContext->temps[idx].name) + "_v");
        if(m_tcgContext->temps[idx].temp_local) {
            std::ostringstream name;
            name << "loc" << (idx - m_tcgContext->nb_globals) << "_v";
            v->setName(name.str());
        } else {
            std::ostringstream name;
            name << "tmp" << (idx - m_tcgContext->nb_globals) << "_v";
            v->setName(name.str());
        }
    }

    if(idx < m_tcgContext->nb_globals) {

        // We need to save a global copy of a value
        m_builder.CreateStore(v, getPtrForValue(idx));

        if(m_tcgContext->temps[idx].fixed_reg) {
            /* Invalidate all dependent global vals and pointers */
            for(int i=0; i<m_tcgContext->nb_globals; ++i) {
                if(i != idx && !m_tcgContext->temps[idx].fixed_reg &&
                                    m_globalsIdx[i] == idx) {
                    delValue(i);
                    delPtrForValue(i);
                }
            }
        }
    } else if(m_tcgContext->temps[idx].temp_local) {
        // We need to save an in-memory copy of a value
        m_builder.CreateStore(v, getPtrForValue(idx));
    }
}

void TCGLLVMContextPrivate::initGlobalsAndLocalTemps()
{
    TCGContext *s = m_tcgContext;

    int reg_to_idx[TCG_TARGET_NB_REGS];
    for(int i=0; i<TCG_TARGET_NB_REGS; ++i)
        reg_to_idx[i] = -1;

    int argNumber = 0;
    for(int i=0; i<s->nb_globals; ++i) {
        if(s->temps[i].fixed_reg) {
            // This global is in fixed host register. We are
            // mapping such registers to function arguments
            m_globalsIdx[i] = argNumber++;
            reg_to_idx[s->temps[i].reg] = i;

        } else {
            // This global is in memory at (mem_reg + mem_offset).
            // Base value is not known yet, so just store mem_reg

            // Change in QEMU according to commit
            // b3a62939561e07bc34493444fa926b6137cba4e8
            m_globalsIdx[i] = s->temps[i].mem_base->reg;
        }
    }

    // Map mem_reg to index for memory-based globals
    for(int i=0; i<s->nb_globals; ++i) {
        if(!s->temps[i].fixed_reg) {
            assert(reg_to_idx[m_globalsIdx[i]] >= 0);
            m_globalsIdx[i] = reg_to_idx[m_globalsIdx[i]];
        }
    }

    // Allocate local temps
    for(int i=s->nb_globals; i<TCG_MAX_TEMPS; ++i) {
        if(s->temps[i].temp_local) {
            m_memValuesPtr[i] = m_builder.CreateAlloca(
                tcgType(s->temps[i].type), 0/*, pName.str()*/);
        }
    }
}

inline BasicBlock* TCGLLVMContextPrivate::getLabel(int idx)
{
    if(!m_labels[idx]) {
        //std::ostringstream bbName;
        //bbName << "label_" << idx;
        m_labels[idx] = BasicBlock::Create(m_context/*, bbName.str()*/);
    }
    return m_labels[idx];
}

inline void TCGLLVMContextPrivate::delLabel(int idx)
{
    if(m_labels[idx] && m_labels[idx]->use_empty() &&
            !m_labels[idx]->getParent())
        delete m_labels[idx];
    m_labels[idx] = nullptr;
}

void TCGLLVMContextPrivate::startNewBasicBlock(BasicBlock *bb)
{
    if(!bb)
        bb = BasicBlock::Create(m_context);
    else
        assert(bb->getParent() == 0);

    if(!m_builder.GetInsertBlock()->getTerminator()) {
        m_builder.CreateBr(bb);
    }

    m_tbFunction->getBasicBlockList().push_back(bb);
    m_builder.SetInsertPoint(bb);

    /* Invalidate all temps */
    for(int i=0; i<TCG_MAX_TEMPS; ++i)
        delValue(i);

    /* Invalidate all pointers to globals */
    for(int i=0; i<m_tcgContext->nb_globals; ++i)
        delPtrForValue(i);
}

/*
 * rwhelan: This is needed since the memory access helpers now need a handle to
 * env
 */
inline Value* TCGLLVMContextPrivate::getEnv() {
    return m_tbFunction->arg_begin();
}

/*
 * rwhelan: This now just calls the helper functions for whole system mode, and
 * we take care of the logging in there.  For user mode, we log in the IR.
 */
inline Value* TCGLLVMContextPrivate::generateQemuMemOp(bool ld,
        Value *value, Value *addr, int flags, int mem_index, int bits, uintptr_t ret_addr)
{
    assert(addr->getType() == intType(TARGET_LONG_BITS));
    assert(ld || value->getType() == intType(bits));
#if TCG_TARGET_REG_BITS != 64
#error "FIXME: Can't compile PANDA LLVM backend on 32-bit host machine."
#endif

#ifdef CONFIG_SOFTMMU
    TCGMemOp opc = get_memop(flags);
    int memIdx = opc & (MO_BSWAP | MO_SIZE);
    uintptr_t helperFuncAddr;

    helperFuncAddr = ld ? (uint64_t) qemu_ld_helpers[bits>>4]:
                           (uint64_t) qemu_st_helpers[bits>>4];

    std::vector<Value*> argValues;
    argValues.reserve(4);
    argValues.push_back(getEnv());
    argValues.push_back(addr);
    if(!ld)
        argValues.push_back(value);
    argValues.push_back(ConstantInt::get(intType(8*sizeof(int)), mem_index));
    argValues.push_back(ConstantInt::get(intType(8*sizeof(uintptr_t)), ret_addr));

    std::vector<llvm::Type*> argTypes;
    argTypes.reserve(4);
    for(int i=0; i<(ld?4:5); ++i)
        argTypes.push_back(argValues[i]->getType());

    FunctionType* helperFunctionTy;
    if (ld) {
        helperFunctionTy = FunctionType::get(intType(bits),
            argTypes, false);
    } else {
        helperFunctionTy = FunctionType::get(llvm::Type::getVoidTy(m_context),
            argTypes, false);
    }

    const char *funcName;
    funcName = ld ? qemu_ld_helper_names[memIdx]:
        qemu_st_helper_names[memIdx];
    assert(funcName);
    Function* helperFunction = m_module->getFunction(funcName);
    if(!helperFunction) {
        helperFunction = Function::Create(
                helperFunctionTy,
                Function::ExternalLinkage, funcName, m_module);
        m_executionEngine->addGlobalMapping(helperFunction,
                                            (void*) helperFuncAddr);
    }

    Value *loadedValue = m_builder.CreateCall(helperFunction, ArrayRef<Value*>(argValues));
    switch (opc & MO_SSIZE) {
    case MO_SB:
        loadedValue = m_builder.CreateTrunc(loadedValue, intType(8));
        return m_builder.CreateSExt(loadedValue, intType(TCG_TARGET_REG_BITS));
    case MO_SW:
        loadedValue = m_builder.CreateTrunc(loadedValue, intType(16));
        return m_builder.CreateSExt(loadedValue, intType(TCG_TARGET_REG_BITS));
#if TCG_TARGET_REG_BITS == 64
    case MO_SL:
        loadedValue = m_builder.CreateTrunc(loadedValue, intType(32));
        return m_builder.CreateSExt(loadedValue, intType(TCG_TARGET_REG_BITS));
#endif
    case MO_UB:
        if (loadedValue->getType()->isVoidTy()) return loadedValue;
        loadedValue = m_builder.CreateTrunc(loadedValue, intType(8));
        return loadedValue;
    case MO_UW:
        if (loadedValue->getType()->isVoidTy()) return loadedValue;
        loadedValue = m_builder.CreateTrunc(loadedValue, intType(16));
        return loadedValue;
    case MO_UL:
        if (loadedValue->getType()->isVoidTy()) return loadedValue;
        loadedValue = m_builder.CreateTrunc(loadedValue, intType(32));
        return loadedValue;
    case MO_Q:
        return loadedValue;
    default:
        assert(false);
        return nullptr;
    }
#else // CONFIG_SOFTMMU
    std::vector<Value*> argValues2;
    addr = m_builder.CreateZExt(addr, wordType());
    addr = m_builder.CreateAdd(addr,
        ConstantInt::get(wordType(), GUEST_BASE));
    addr = m_builder.CreateIntToPtr(addr, intPtrType(bits));
    if(ld) {
        return m_builder.CreateLoad(addr);
    } else {
        m_builder.CreateStore(value, addr);
        return nullptr;
    }
#endif // CONFIG_SOFTMMU
}

int TCGLLVMContextPrivate::generateOperation(int opc, const TCGOp *op,
    const TCGArg *args)
{
    Value *v;
    TCGOpDef &def = tcg_op_defs[opc];
    int nb_args = def.nb_args;
    int op_size = def.flags & TCG_OPF_64BIT ? 64 : 32;

    switch(opc) {
    case INDEX_op_insn_start:
        break;

    case INDEX_op_discard:
        delValue(args[0]);
        break;

    case INDEX_op_call:
        {
            int nb_oargs = op->callo;
            int nb_iargs = op->calli;
            nb_args = nb_oargs + nb_iargs + def.nb_cargs + 1;

            std::vector<Value*> argValues;
            std::vector<llvm::Type*> argTypes;
            argValues.reserve(nb_iargs);
            argTypes.reserve(nb_iargs);
            for(int i=0; i < nb_iargs/*-1*/; ++i) {
                TCGArg arg = args[nb_oargs + i /*+ 1*/];
                if(arg != TCG_CALL_DUMMY_ARG) {
                    Value *v = getValue(arg);
                    argValues.push_back(v);
                    argTypes.push_back(v->getType());
                }
            }

            assert(nb_oargs == 0 || nb_oargs == 1);

            //args[0] contains ptr to store to. Set return type based on it
            llvm::Type* retType = nb_oargs == 0 ?
                llvm::Type::getVoidTy(m_context) : wordType(getValueBits(args[0]));

            Value* helperAddr = ConstantInt::get(intType(sizeof(uintptr_t)*8),
                args[nb_oargs + nb_iargs]);
            Value* result;

            tcg_target_ulong helperAddrC = (tcg_target_ulong)
                   cast<ConstantInt>(helperAddr)->getZExtValue();

            const char *helperName = tcg_find_helper(m_tcgContext,
                                                     (uintptr_t)helperAddrC);
            assert(helperName);

            std::string funcName = std::string("helper_") + helperName;
            Function* helperFunc = m_module->getFunction(funcName);
            if(!helperFunc) {
                helperFunc = Function::Create(
                        FunctionType::get(retType, argTypes, false),
                        Function::ExternalLinkage, funcName, m_module);
                m_executionEngine->addGlobalMapping(helperFunc,
                                                    (void*) helperAddrC);
            }

            result = m_builder.CreateCall(helperFunc,
                                          ArrayRef<Value*>(argValues));

            /* Invalidate in-memory values because
             * function might have changed them */
            for(int i=0; i<m_tcgContext->nb_globals; ++i)
                delValue(i);

            for(int i=m_tcgContext->nb_globals; i<TCG_MAX_TEMPS; ++i)
                if(m_tcgContext->temps[i].temp_local)
                    delValue(i);

            /* Invalidate all pointers to globals */
            for(int i=0; i<m_tcgContext->nb_globals; ++i)
                delPtrForValue(i);

            if(nb_oargs == 1) {
                setValue(args[0], result);
            }

        }
        break;

    case INDEX_op_br:
        m_builder.CreateBr(getLabel(((TCGLabel *)args[0])->id));
        startNewBasicBlock();
        break;

#define __OP_BRCOND_C(tcg_cond, cond)                               \
            case tcg_cond:                                          \
                v = m_builder.CreateICmp ## cond(                   \
                        getValue(args[0]), getValue(args[1]));      \
            break;

#define __OP_BRCOND(opc_name, bits)                                 \
    case opc_name: {                                                \
        assert(getValue(args[0])->getType() == intType(bits));      \
        assert(getValue(args[1])->getType() == intType(bits));      \
        switch(args[2]) {                                           \
            __OP_BRCOND_C(TCG_COND_EQ,   EQ)                        \
            __OP_BRCOND_C(TCG_COND_NE,   NE)                        \
            __OP_BRCOND_C(TCG_COND_LT,  SLT)                        \
            __OP_BRCOND_C(TCG_COND_GE,  SGE)                        \
            __OP_BRCOND_C(TCG_COND_LE,  SLE)                        \
            __OP_BRCOND_C(TCG_COND_GT,  SGT)                        \
            __OP_BRCOND_C(TCG_COND_LTU, ULT)                        \
            __OP_BRCOND_C(TCG_COND_GEU, UGE)                        \
            __OP_BRCOND_C(TCG_COND_LEU, ULE)                        \
            __OP_BRCOND_C(TCG_COND_GTU, UGT)                        \
            default:                                                \
                tcg_abort();                                        \
        }                                                           \
        BasicBlock* bb = BasicBlock::Create(m_context);             \
        m_builder.CreateCondBr(v,                                   \
            getLabel(arg_label(args[3])->id), bb);                  \
        startNewBasicBlock(bb);                                     \
    } break;

    __OP_BRCOND(INDEX_op_brcond_i32, 32)

#if TCG_TARGET_REG_BITS == 64
    __OP_BRCOND(INDEX_op_brcond_i64, 64)
#endif

#undef __OP_BRCOND_C
#undef __OP_BRCOND

#define __OP_SETCOND_C(tcg_cond, cond)                              \
            case tcg_cond:                                          \
                v = m_builder.CreateICmp ## cond(v1, v2);           \
            break;

    /* XXX setcond - why is this needed if it's unused? */

#define __OP_SETCOND(opc_name, bits, cond, t, f)                    \
    case opc_name: {                                                \
        Value* v1  = getValue(args[1]);                             \
        Value* v2  = getValue(args[2]);                             \
        assert(v1->getType() == intType(bits));                     \
        assert(v2->getType() == intType(bits));                     \
        switch((cond)) {                                            \
            __OP_SETCOND_C(TCG_COND_EQ,   EQ)                       \
            __OP_SETCOND_C(TCG_COND_NE,   NE)                       \
            __OP_SETCOND_C(TCG_COND_LT,  SLT)                       \
            __OP_SETCOND_C(TCG_COND_GE,  SGE)                       \
            __OP_SETCOND_C(TCG_COND_LE,  SLE)                       \
            __OP_SETCOND_C(TCG_COND_GT,  SGT)                       \
            __OP_SETCOND_C(TCG_COND_LTU, ULT)                       \
            __OP_SETCOND_C(TCG_COND_GEU, UGE)                       \
            __OP_SETCOND_C(TCG_COND_LEU, ULE)                       \
            __OP_SETCOND_C(TCG_COND_GTU, UGT)                       \
            default:                                                \
                tcg_abort();                                        \
        }                                                           \
        setValue(args[0], m_builder.CreateSelect(v, (t), (f)));     \
    } break;

    __OP_SETCOND(INDEX_op_setcond_i32, 32, args[3],
            constInt(32, 1), constInt(32, 0))
#ifdef TCG_TARGET_HAS_movcond_i32
    __OP_SETCOND(INDEX_op_movcond_i32, 32, args[5],
            getValue(args[3]), getValue(args[4]))
#endif

#if TCG_TARGET_REG_BITS == 64
    __OP_SETCOND(INDEX_op_setcond_i64, 64, args[3],
            constInt(64, 1), constInt(64, 0))
#ifdef TCG_TARGET_HAS_movcond_i64
    __OP_SETCOND(INDEX_op_movcond_i64, 64, args[5],
            getValue(args[3]), getValue(args[4]))
#endif
#endif

#undef __OP_SETCOND_C
#undef __OP_SETCOND

    case INDEX_op_set_label:
        assert(getLabel(arg_label(args[0])->id)->getParent() == 0);
        startNewBasicBlock(getLabel(arg_label(args[0])->id));
        break;

    case INDEX_op_movi_i32:
        setValue(args[0], ConstantInt::get(intType(32), args[1]));
        break;

    case INDEX_op_mov_i32:
        // Move operation may perform truncation of the value
        assert(getValue(args[1])->getType() == intType(32) ||
                getValue(args[1])->getType() == intType(64));
        setValue(args[0],
                m_builder.CreateTrunc(getValue(args[1]), intType(32)));
        break;

#if TCG_TARGET_REG_BITS == 64
    case INDEX_op_movi_i64:
        setValue(args[0], ConstantInt::get(intType(64), args[1]));
        break;

    case INDEX_op_mov_i64:
        assert(getValue(args[1])->getType() == intType(64));
        setValue(args[0], getValue(args[1]));
        break;
#endif

    /* size extensions */
#define __EXT_OP(opc_name, truncBits, opBits, signE )               \
    case opc_name:                                                  \
        /*                                                          \
        assert(getValue(args[1])->getType() == intType(opBits) ||   \
               getValue(args[1])->getType() == intType(truncBits)); \
        */                                                          \
        setValue(args[0], m_builder.Create ## signE ## Ext(         \
                m_builder.CreateTrunc(                              \
                    getValue(args[1]), intType(truncBits)),         \
                intType(opBits)));                                  \
        break;

    __EXT_OP(INDEX_op_ext8s_i32,   8, 32, S)
    __EXT_OP(INDEX_op_ext8u_i32,   8, 32, Z)
    __EXT_OP(INDEX_op_ext16s_i32, 16, 32, S)
    __EXT_OP(INDEX_op_ext16u_i32, 16, 32, Z)
    __EXT_OP(INDEX_op_extu_i32_i64, 32, 64, Z)

#if TCG_TARGET_REG_BITS == 64
    __EXT_OP(INDEX_op_ext8s_i64,   8, 64, S)
    __EXT_OP(INDEX_op_ext8u_i64,   8, 64, Z)
    __EXT_OP(INDEX_op_ext16s_i64, 16, 64, S)
    __EXT_OP(INDEX_op_ext16u_i64, 16, 64, Z)
    __EXT_OP(INDEX_op_ext32s_i64, 32, 64, S)
    __EXT_OP(INDEX_op_ext32u_i64, 32, 64, Z)
#endif

#undef __EXT_OP

    /* load/store */
#define __LD_OP(opc_name, memBits, regBits, signE)                  \
    case opc_name:  {                                               \
        TCGTemp &temp = m_tcgContext->temps[args[0]];               \
        assert(!m_tcgContext->temps[args[1]].name                   \
                || !strcmp(m_tcgContext->temps[args[1]].name, "env"));\
        v = getEnvOffsetPtr(args[2], temp);                         \
        v = m_builder.CreatePointerCast(v, intPtrType(memBits)); \
        v = m_builder.CreateLoad(v);                                \
        setValue(args[0], m_builder.Create ## signE ## Ext(         \
                    v, intType(regBits)));                          \
    } break;

#define __ST_OP(opc_name, memBits, regBits)                         \
    case opc_name:  {                                               \
        TCGTemp &temp = m_tcgContext->temps[args[0]];               \
        assert(getValue(args[0])->getType() == intType(regBits));   \
        assert(!m_tcgContext->temps[args[1]].name                   \
                || !strcmp(m_tcgContext->temps[args[1]].name, "env"));\
        Value* valueToStore = getValue(args[0]);                    \
        Value* storePtr = getEnvOffsetPtr(args[2], temp);           \
        storePtr = m_builder.CreatePointerCast(storePtr, intPtrType(memBits)); \
        m_builder.CreateStore(m_builder.CreateTrunc(                \
                valueToStore, intType(memBits)), storePtr);         \
    } break;

    __LD_OP(INDEX_op_ld8u_i32,   8, 32, Z)
    __LD_OP(INDEX_op_ld8s_i32,   8, 32, S)
    __LD_OP(INDEX_op_ld16u_i32, 16, 32, Z)
    __LD_OP(INDEX_op_ld16s_i32, 16, 32, S)
    __LD_OP(INDEX_op_ld_i32,    32, 32, Z)

    __ST_OP(INDEX_op_st8_i32,   8, 32)
    __ST_OP(INDEX_op_st16_i32, 16, 32)
    __ST_OP(INDEX_op_st_i32,   32, 32)

#if TCG_TARGET_REG_BITS == 64
    __LD_OP(INDEX_op_ld8u_i64,   8, 64, Z)
    __LD_OP(INDEX_op_ld8s_i64,   8, 64, S)
    __LD_OP(INDEX_op_ld16u_i64, 16, 64, Z)
    __LD_OP(INDEX_op_ld16s_i64, 16, 64, S)
    __LD_OP(INDEX_op_ld32u_i64, 32, 64, Z)
    __LD_OP(INDEX_op_ld32s_i64, 32, 64, S)
    __LD_OP(INDEX_op_ld_i64,    64, 64, Z)

    __ST_OP(INDEX_op_st8_i64,   8, 64)
    __ST_OP(INDEX_op_st16_i64, 16, 64)
    __ST_OP(INDEX_op_st32_i64, 32, 64)
    __ST_OP(INDEX_op_st_i64,   64, 64)
#endif

#undef __LD_OP
#undef __ST_OP

    /* arith */
#define __ARITH_OP(opc_name, op, bits)                              \
    case opc_name: {                                                \
        Value *v1 = getValue(args[1]);                              \
        Value *v2 = getValue(args[2]);                              \
        adjustTypeSize(bits, &v1, &v2);                             \
        assert(v1->getType() == intType(bits));                     \
        assert(v2->getType() == intType(bits));                     \
        setValue(args[0], m_builder.Create ## op(v1, v2));          \
    } break;

#define __ARITH_OP_COMPUTE(opc_name, bits, compute)                 \
    case opc_name: {                                                \
        Value *v1 = getValue(args[1]);                              \
        Value *v2 = getValue(args[2]);                              \
        adjustTypeSize(bits, &v1, &v2);                             \
        assert(v1->getType() == intType(bits));                     \
        assert(v2->getType() == intType(bits));                     \
        Value *out = compute;                                       \
        setValue(args[0], out);                                     \
    } break;

#define __ARITH_OP_DIV2(opc_name, signE, bits)                      \
    case opc_name:                                                  \
        assert(getValue(args[2])->getType() == intType(bits));      \
        assert(getValue(args[3])->getType() == intType(bits));      \
        assert(getValue(args[4])->getType() == intType(bits));      \
        v = m_builder.CreateShl(                                    \
                m_builder.CreateZExt(                               \
                    getValue(args[3]), intType(bits*2)),            \
                bits);                                              \
        v = m_builder.CreateOr(v,                                   \
                m_builder.CreateZExt(                               \
                    getValue(args[2]), intType(bits*2)));           \
        setValue(args[0], m_builder.Create ## signE ## Div(         \
                v, getValue(args[4])));                             \
        setValue(args[1], m_builder.Create ## signE ## Rem(         \
                v, getValue(args[4])));                             \
        break;

#define __ARITH_OP_ROT(opc_name, op1, op2, bits)                    \
    case opc_name:                                                  \
        assert(getValue(args[1])->getType() == intType(bits));      \
        assert(getValue(args[2])->getType() == intType(bits));      \
        v = m_builder.CreateSub(                                    \
                ConstantInt::get(intType(bits), bits),              \
                getValue(args[2]));                                 \
        setValue(args[0], m_builder.CreateOr(                       \
                m_builder.Create ## op1 (                           \
                    getValue(args[1]), getValue(args[2])),          \
                m_builder.Create ## op2 (                           \
                    getValue(args[1]), v)));                        \
        break;

#define __ARITH_OP_I(opc_name, op, i, bits)                         \
    case opc_name:                                                  \
        assert(getValue(args[1])->getType() == intType(bits));      \
        setValue(args[0], m_builder.Create ## op(                   \
                    ConstantInt::get(intType(bits), i),             \
                    getValue(args[1])));                            \
        break;

#define __ARITH_OP_BSWAP(opc_name, sBits, bits)                     \
    case opc_name: {                                                \
        assert(getValue(args[1])->getType() == intType(bits));      \
        llvm::Type* Tys[] = { intType(sBits) };                     \
        Function *bswap = Intrinsic::getDeclaration(m_module,       \
                Intrinsic::bswap, ArrayRef<llvm::Type*>(Tys,1));    \
        v = m_builder.CreateTrunc(getValue(args[1]),intType(sBits));\
        setValue(args[0], m_builder.CreateZExt(                     \
                m_builder.CreateCall(bswap, v), intType(bits)));    \
        } break;

    /* for ops of type op out_lo, out_hi, in, in */
#define __ARITH_OP_DECOMPOSE(opc_name, op, extend, bits)            \
    case opc_name: {                                                \
        assert(getValue(args[2])->getType() == intType(bits));     \
        assert(getValue(args[3])->getType() == intType(bits));     \
        Value *ext1 = m_builder.Create ## extend(                   \
                getValue(args[2]), intType(bits * 2));              \
        Value *ext2 = m_builder.Create ## extend(                   \
                getValue(args[3]), intType(bits * 2));              \
        Value *full = m_builder.Create ## op(ext1, ext2);           \
        setValue(args[0], m_builder.CreateTrunc(                    \
                    full, intType(bits)));                          \
        setValue(args[1], m_builder.CreateTrunc(                    \
                    m_builder.CreateLShr(full, bits),               \
                    intType(bits)));                                \
        } break;

// for ops of type op out_low, out_high, in_low, in_high, in_low, in_high
#define __ARITH_OP_DECOMPOSE_2(opc_name, op, bits)                     \
    case opc_name: {                                                   \
        assert(getValue(args[2])->getType() == intType(bits));         \
        assert(getValue(args[3])->getType() == intType(bits));         \
        assert(getValue(args[4])->getType() == intType(bits));         \
        assert(getValue(args[5])->getType() == intType(bits));         \
        Value *ext1 = m_builder.CreateZExt(                            \
                getValue(args[2]), intType(bits*2));                   \
        Value *ext2 = m_builder.CreateShl(                             \
                m_builder.CreateZExt(                                  \
                    getValue(args[3]), intType(bits*2)),               \
                bits);                                 \
        Value *first_arg = m_builder.CreateOr(ext1, ext2);             \
        Value *ext3 = m_builder.CreateZExt(                            \
                getValue(args[4]), intType(bits*2));                   \
        Value *ext4 = m_builder.CreateShl(                             \
                m_builder.CreateZExt(                                  \
                    getValue(args[5]), intType(bits*2)),               \
                bits);                                 \
        Value *second_arg = m_builder.CreateOr(ext3, ext4);            \
        Value *full = m_builder.Create ## op(first_arg, second_arg);    \
        setValue(args[0], m_builder.CreateTrunc(                        \
                    full, intType(bits)));                              \
        setValue(args[1], m_builder.CreateTrunc(                        \
                    m_builder.CreateLShr(full, bits),                   \
                    intType(bits)));                                    \
        } break;

    __ARITH_OP(INDEX_op_add_i32, Add, 32)
    __ARITH_OP(INDEX_op_sub_i32, Sub, 32)
    __ARITH_OP(INDEX_op_mul_i32, Mul, 32)

#ifdef TCG_TARGET_HAS_add2_i32
    __ARITH_OP_DECOMPOSE_2(INDEX_op_add2_i32, Add, 32)
    __ARITH_OP_DECOMPOSE_2(INDEX_op_sub2_i32, Sub, 32)
#endif

#ifdef TCG_TARGET_HAS_mulu2_i32
    __ARITH_OP_DECOMPOSE(INDEX_op_mulu2_i32, Mul, ZExt, 32)
#endif
#ifdef TCG_TARGET_HAS_muls2_i32
    __ARITH_OP_DECOMPOSE(INDEX_op_muls2_i32, Mul, SExt, 32)
#endif

#ifdef TCG_TARGET_HAS_div_i32
    __ARITH_OP(INDEX_op_div_i32,  SDiv, 32)
    __ARITH_OP(INDEX_op_divu_i32, UDiv, 32)
    __ARITH_OP(INDEX_op_rem_i32,  SRem, 32)
    __ARITH_OP(INDEX_op_remu_i32, URem, 32)
#endif
    __ARITH_OP_DIV2(INDEX_op_div2_i32,  S, 32)
    __ARITH_OP_DIV2(INDEX_op_divu2_i32, U, 32)

    __ARITH_OP(INDEX_op_and_i32, And, 32)
    __ARITH_OP(INDEX_op_or_i32,   Or, 32)
    __ARITH_OP(INDEX_op_xor_i32, Xor, 32)

    __ARITH_OP_COMPUTE(INDEX_op_andc_i64, 64,
            m_builder.CreateAnd(v1, m_builder.CreateNot(v2)))

    __ARITH_OP_COMPUTE(INDEX_op_andc_i32, 32,
            m_builder.CreateAnd(v1, m_builder.CreateNot(v2)))

    __ARITH_OP_COMPUTE(INDEX_op_orc_i32, 32,
            m_builder.CreateOr(v1, m_builder.CreateNot(v2)))

    __ARITH_OP_COMPUTE(INDEX_op_eqv_i32, 32,
            m_builder.CreateNot(m_builder.CreateXor(v1, v2)))

    __ARITH_OP_COMPUTE(INDEX_op_nand_i32, 32,
            m_builder.CreateNot(m_builder.CreateAnd(v1, v2)))

    __ARITH_OP_COMPUTE(INDEX_op_nor_i32, 32,
            m_builder.CreateNot(m_builder.CreateOr(v1, v2)))

    __ARITH_OP(INDEX_op_shl_i32,  Shl, 32)
    __ARITH_OP(INDEX_op_shr_i32, LShr, 32)
    __ARITH_OP(INDEX_op_sar_i32, AShr, 32)

    __ARITH_OP_ROT(INDEX_op_rotl_i32, Shl, LShr, 32)
    __ARITH_OP_ROT(INDEX_op_rotr_i32, LShr, Shl, 32)

    __ARITH_OP_I(INDEX_op_not_i32, Xor, (uint64_t) -1, 32)
    __ARITH_OP_I(INDEX_op_neg_i32, Sub, 0, 32)

    __ARITH_OP_BSWAP(INDEX_op_bswap16_i32, 16, 32)
    __ARITH_OP_BSWAP(INDEX_op_bswap32_i32, 32, 32)

#if TCG_TARGET_REG_BITS == 64
    __ARITH_OP(INDEX_op_add_i64, Add, 64)
    __ARITH_OP(INDEX_op_sub_i64, Sub, 64)
    __ARITH_OP(INDEX_op_mul_i64, Mul, 64)

#ifdef TCG_TARGET_HAS_mulu2_i64
    __ARITH_OP_DECOMPOSE(INDEX_op_mulu2_i64, Mul, ZExt, 64)
#endif
#ifdef TCG_TARGET_HAS_muls2_i64
    __ARITH_OP_DECOMPOSE(INDEX_op_muls2_i64, Mul, SExt, 64)
#endif

#ifdef TCG_TARGET_HAS_div_i64
    __ARITH_OP(INDEX_op_div_i64,  SDiv, 64)
    __ARITH_OP(INDEX_op_divu_i64, UDiv, 64)
    __ARITH_OP(INDEX_op_rem_i64,  SRem, 64)
    __ARITH_OP(INDEX_op_remu_i64, URem, 64)
#else
    __ARITH_OP_DIV2(INDEX_op_div2_i64,  S, 64)
    __ARITH_OP_DIV2(INDEX_op_divu2_i64, U, 64)
#endif

    __ARITH_OP(INDEX_op_and_i64, And, 64)
    __ARITH_OP(INDEX_op_or_i64,   Or, 64)
    __ARITH_OP(INDEX_op_xor_i64, Xor, 64)

    __ARITH_OP(INDEX_op_shl_i64,  Shl, 64)
    __ARITH_OP(INDEX_op_shr_i64, LShr, 64)
    __ARITH_OP(INDEX_op_sar_i64, AShr, 64)

    __ARITH_OP_ROT(INDEX_op_rotl_i64, Shl, LShr, 64)
    __ARITH_OP_ROT(INDEX_op_rotr_i64, LShr, Shl, 64)

    __ARITH_OP_I(INDEX_op_not_i64, Xor, (uint64_t) -1, 64)
    __ARITH_OP_I(INDEX_op_neg_i64, Sub, 0, 64)

    __ARITH_OP_BSWAP(INDEX_op_bswap16_i64, 16, 64)
    __ARITH_OP_BSWAP(INDEX_op_bswap32_i64, 32, 64)
    __ARITH_OP_BSWAP(INDEX_op_bswap64_i64, 64, 64)
#endif

#undef __ARITH_OP_BSWAP
#undef __ARITH_OP_I
#undef __ARITH_OP_ROT
#undef __ARITH_OP_DIV2
#undef __ARITH_OP

// retaddr is set to 0xDEADBEEF for now...see note in softmmu_template.h
#define __OP_QEMU_ST(opc_name)                                      \
    case opc_name: {                                                \
        TCGMemOp op = get_memop(args[2]);                           \
        bool signE = op & MO_SIGN;                                  \
        int bits = (1 << (op & MO_SIZE)) * 8;                       \
        unsigned memIndex = get_mmuidx(args[2]);                    \
        generateQemuMemOp(false,                                    \
            m_builder.CreateIntCast(                                \
                getValue(args[0]), intType(bits), signE),           \
            getValue(args[1]), args[2], memIndex, bits, 0xDEADBEEF);\
        break; }                                                    \

#define __OP_QEMU_LD(opc_name)                                      \
    case opc_name: {                                                \
        TCGMemOp op = get_memop(args[2]);                           \
        bool signE = op & MO_SIGN;                                  \
        int bits = (1 << (op & MO_SIZE)) * 8;                       \
        unsigned memIndex = get_mmuidx(args[2]);                    \
        Value *v = generateQemuMemOp(true, nullptr,                 \
            getValue(args[1]), args[2], memIndex, bits, 0xDEADBEEF);\
        setValue(args[0], m_builder.CreateIntCast(                  \
            v, intType(std::max(TARGET_LONG_BITS, bits)), signE));  \
        break; }                                                    \

    __OP_QEMU_ST(INDEX_op_qemu_st_i32)
    __OP_QEMU_LD(INDEX_op_qemu_ld_i32)

    /* QEMU specific */
#if TCG_TARGET_REG_BITS == 64
    __OP_QEMU_ST(INDEX_op_qemu_st_i64)
    __OP_QEMU_LD(INDEX_op_qemu_ld_i64)
#endif

#undef __OP_QEMU_LD
#undef __OP_QEMU_ST

    case INDEX_op_exit_tb:
        m_builder.CreateRet(ConstantInt::get(wordType(), args[0]));
        break;

    case INDEX_op_goto_tb:
        /* XXX: tb linking is disabled */
        break;

    case INDEX_op_deposit_i32: {
        Value *arg1 = getValue(args[1]);
        Value *arg2 = getValue(args[2]);
        arg2 = m_builder.CreateTrunc(arg2, intType(32));

        uint32_t ofs = args[3];
        uint32_t len = args[4];

        if (ofs == 0 && len == 32) {
            setValue(args[0], arg2);
            break;
        }

        uint32_t mask = (1u << len) - 1;
        Value *t1, *ret;
        if (ofs + len < 32) {
            t1 = m_builder.CreateAnd(arg2, APInt(32, mask));
            t1 = m_builder.CreateShl(t1, APInt(32, ofs));
        } else {
            t1 = m_builder.CreateShl(arg2, APInt(32, ofs));
        }

        ret = m_builder.CreateAnd(arg1, APInt(32, ~(mask << ofs)));
        ret = m_builder.CreateOr(ret, t1);
        setValue(args[0], ret);
    }
    break;

    case INDEX_op_deposit_i64: {
        Value *arg1 = getValue(args[1]);
        Value *arg2 = getValue(args[2]);
        arg2 = m_builder.CreateTrunc(arg2, intType(64));

        uint64_t ofs = args[3];
        uint64_t len = args[4];

        if (ofs == 0 && len == 64) {
            setValue(args[0], arg2);
            break;
        }

        uint64_t mask = (1u << len) - 1;
        Value *t1, *ret;
        if (ofs + len < 64) {
            t1 = m_builder.CreateAnd(arg2, APInt(64, mask));
            t1 = m_builder.CreateShl(t1, APInt(64, ofs));
        } else {
            t1 = m_builder.CreateShl(arg2, APInt(64, ofs));
        }

        ret = m_builder.CreateAnd(arg1, APInt(64, ~(mask << ofs)));
        ret = m_builder.CreateOr(ret, t1);
        setValue(args[0], ret);
    }
    break;

    case INDEX_op_sextract_i32:
    case INDEX_op_sextract_i64:
    case INDEX_op_extract_i32:
    case INDEX_op_extract_i64: {
        Value *source = getValue(args[1]);
        uint64_t offset = args[2];
        uint64_t len = args[3];

        Value *shifted = offset == 0 ? source
            : m_builder.CreateLShr(source, APInt(op_size, offset));
        uint64_t mask = (1UL << len) - 1;
        // len == op_size should imply offset == 0.
        Value *ret = len == op_size ? shifted
            : m_builder.CreateAnd(shifted, APInt(op_size, mask));
        if (len < op_size
                && (opc == INDEX_op_sextract_i32
                    || opc == INDEX_op_sextract_i64)) {
            assert(len % 8 == 0);
            ret = m_builder.CreateTrunc(ret, intType(len));
            ret = m_builder.CreateSExt(ret, intType(op_size));
        }
        setValue(args[0], ret);
    }
    break;

    case INDEX_op_ctz_i32:
    case INDEX_op_ctz_i64:
    case INDEX_op_clz_i32:
    case INDEX_op_clz_i64: {
        Value *source = getValue(args[1]);
        Value *default_ = getValue(args[2]);
        Value *isZero = m_builder.CreateICmpEQ(source, constInt(op_size, 0));
        llvm::Type* Tys[] = { intType(op_size) };
        Intrinsic::ID intrinsicID =
            (opc == INDEX_op_ctz_i32 || opc == INDEX_op_ctz_i64)
            ? Intrinsic::cttz : Intrinsic::ctlz;
        Function *intrinsic = Intrinsic::getDeclaration(m_module,
                intrinsicID, llvm::ArrayRef<llvm::Type*>(Tys, 1));
        // declare i32  @llvm.ctlz.i32 (i32  <src>, i1 <is_zero_undef>)
        llvm::Value* callArgs[] = { source, constInt(1, false) };
        Value *result = m_builder.CreateCall(intrinsic,
                llvm::ArrayRef<llvm::Value*>(callArgs, 2));
        // select args go condition, ifTrue, ifFalse
        Value *ret = m_builder.CreateSelect(isZero, default_, result);
        setValue(args[0], ret);
    }
    break;

    default:
        std::cerr << "ERROR: unknown TCG micro operation '"
                  << def.name << "'" << std::endl;
        tcg_abort();
        break;
    }

    return nb_args;
}

void TCGLLVMContextPrivate::generateCode(TCGContext *s, TranslationBlock *tb)
{
    /* Create new function for current translation block */
    /* TODO: compute the checksum of the tb to see if we can reuse some code */
    std::ostringstream fName;

    fName << "tcg-llvm-tb-" << (m_tbCount++) << "-" << std::hex << tb->pc;

#ifdef CONFIG_USER_ONLY
    const char *symName = lookup_symbol(tb->pc);
    fName << "-" << symName;
#endif

    /*
    if(m_tbFunction)
        m_tbFunction->eraseFromParent();
    */

    if (m_CPUArchStateType == nullptr) {
        init_llvm_helpers();
        m_CPUArchStateType = m_module->getTypeByName(m_CPUArchStateName);
    }
    assert(m_CPUArchStateType);

    llvm::Type *pCPUArchStateType =
        PointerType::getUnqual(m_CPUArchStateType);
    FunctionType *tbFunctionType = FunctionType::get(wordType(),
            std::vector<llvm::Type*>{pCPUArchStateType}, false);
    m_tbFunction = Function::Create(tbFunctionType,
            Function::PrivateLinkage, fName.str(), m_module);
    BasicBlock *basicBlock = BasicBlock::Create(m_context,
            "entry", m_tbFunction);
    m_builder.SetInsertPoint(basicBlock);

    m_tcgContext = s;

    /* Prepare globals and temps information */
    initGlobalsAndLocalTemps();

    LLVMContext &C = m_context;
    MDNode *PCUpdateMD = MDNode::get(C, MDString::get(C, "pcupdate"));
    MDNode *RRUpdateMD = MDNode::get(C, MDString::get(C, "rrupdate"));
    MDNode *RuntimeMD = MDNode::get(C, MDString::get(C, "runtime"));

    /* Init int for adding offsets to env */
    m_envInt = m_builder.CreatePtrToInt(m_tbFunction->arg_begin(), wordType());
    Instruction *EnvI2PI = dyn_cast<Instruction>(m_envInt);
    if (EnvI2PI) EnvI2PI->setMetadata("host", RuntimeMD);

    /* Setup panda_guest_pc */
    Constant *GuestPCPtrInt = constInt(sizeof(uintptr_t) * 8,
            (uintptr_t)&first_cpu->panda_guest_pc);
    Value *GuestPCPtr = m_builder.CreateIntToPtr(GuestPCPtrInt, intPtrType(64), "guestpc");

    /* Setup rr_guest_instr_count stores */
    Constant *InstrCountPtrInt = constInt(sizeof(uintptr_t) * 8,
            (uintptr_t)&first_cpu->rr_guest_instr_count);
    Value *InstrCountPtr = m_builder.CreateIntToPtr(
            InstrCountPtrInt, intPtrType(64), "rrgicp");
    Instruction *InstrCount = m_builder.CreateLoad(InstrCountPtr, true, "rrgic");
    InstrCount->setMetadata("host", RRUpdateMD);
    Value *One64 = constInt(64, 1);

    /* Generate code for each opc */
    const TCGArg *args;
    TCGOp *op;
    for(int opc_index = s->gen_op_buf[0].next; opc_index != 0;
            opc_index = op->next) {
        op = &s->gen_op_buf[opc_index];
        args = &s->gen_opparam_buf[op->args];
        int opc = op->opc;

        if (opc == INDEX_op_insn_start) {
            // volatile store of current PC
            Constant *PC = ConstantInt::get(intType(64), args[0]);
            Instruction *GuestPCSt = m_builder.CreateStore(PC, GuestPCPtr, true);
            // TRL 2014 hack to annotate that last instruction as the one
            // that sets PC
            GuestPCSt->setMetadata("host", PCUpdateMD);

            InstrCount = dyn_cast<Instruction>(
                    m_builder.CreateAdd(InstrCount, One64, "rrgic"));
            assert(InstrCount);
            Instruction *RRSt = m_builder.CreateStore(InstrCount, InstrCountPtr, true);
            InstrCount->setMetadata("host", RRUpdateMD);
            RRSt->setMetadata("host", RRUpdateMD);
        }

        args += generateOperation(opc, op, args);
    }

    /* Finalize function */
    if(!isa<ReturnInst>(m_tbFunction->back().back()))
        m_builder.CreateRet(ConstantInt::get(wordType(), 0));

    /* Clean up unused m_values */
    for(int i=0; i<TCG_MAX_TEMPS; ++i)
        delValue(i);

    /* Delete pointers after deleting values */
    for(int i=0; i<TCG_MAX_TEMPS; ++i)
        delPtrForValue(i);

    for(int i=0; i<TCG_MAX_LABELS; ++i)
        delLabel(i);

    for (auto &it : m_envOffsetValues) {
        freeValue(it.second);
    }
    m_envOffsetValues.clear();

    // run all specified function passes
    m_functionPassManager->run(*m_tbFunction);

#ifndef NDEBUG
    verifyFunction(*m_tbFunction);
#endif

    tb->llvm_function = m_tbFunction;

    if(execute_llvm || qemu_loglevel_mask(CPU_LOG_LLVM_ASM)) {
        tb->llvm_tc_ptr = (uint8_t*)
                m_executionEngine->getPointerToFunction(m_tbFunction);
        tb->llvm_tc_end = tb->llvm_tc_ptr +
                m_jitMemoryManager->getFunctionSize(m_tbFunction);

        assert(tb->llvm_tc_ptr);
        assert(tb->llvm_tc_end > tb->llvm_tc_ptr);
    } else {
        tb->llvm_tc_ptr = 0;
        tb->llvm_tc_end = 0;
    }

    if(qemu_loglevel_mask(CPU_LOG_LLVM_IR)) {
        std::string fcnString;
        llvm::raw_string_ostream s(fcnString);
        s << *m_tbFunction;
        qemu_log("OUT (LLVM IR):\n");
        qemu_log("%s", s.str().c_str());
        qemu_log("\n");
        qemu_log_flush();
    }
}

/***********************************/
/* External interface for C++ code */

TCGLLVMContext::TCGLLVMContext()
        : m_private(new TCGLLVMContextPrivate)
{
}

TCGLLVMContext::~TCGLLVMContext()
{
    delete m_private;
}

llvm::FunctionPassManager* TCGLLVMContext::getFunctionPassManager() const
{
    return m_private->getFunctionPassManager();
}

void TCGLLVMContext::deleteExecutionEngine()
{
    m_private->deleteExecutionEngine();
}

LLVMContext& TCGLLVMContext::getLLVMContext()
{
    return m_private->m_context;
}

Module* TCGLLVMContext::getModule()
{
    return m_private->m_module;
}

ExecutionEngine* TCGLLVMContext::getExecutionEngine()
{
    return m_private->m_executionEngine;
}

void TCGLLVMContext::generateCode(TCGContext *s, TranslationBlock *tb)
{
    assert(tb->tcg_llvm_context == nullptr);
    assert(tb->llvm_function == nullptr);

    tb->tcg_llvm_context = this;
    m_private->generateCode(s, tb);
}

void TCGLLVMContext::writeModule(const char *path)
{
    std::string Error;
    raw_fd_ostream outfile(path, Error, raw_fd_ostream::F_Binary);
    std::string err;
    if (verifyModule(*getModule(), llvm::PrintMessageAction, &err)) {
        printf("%s\n", err.c_str());
        exit(1);
    }
    WriteBitcodeToFile(getModule(), outfile);
}

/*****************************/
/* Functions for QEMU c code */

void tcg_llvm_initialize()
{
    assert(tcg_llvm_ctx == nullptr);
    assert(llvm_start_multithreaded());
    tcg_llvm_ctx = new TCGLLVMContext;
}

void tcg_llvm_destroy()
{
    assert(tcg_llvm_ctx != nullptr);
    delete tcg_llvm_ctx;
    tcg_llvm_ctx = nullptr;
}

void tcg_llvm_gen_code(TCGLLVMContext *l, TCGContext *s, TranslationBlock *tb)
{
    l->generateCode(s, tb);
}

void tcg_llvm_tb_alloc(TranslationBlock *tb)
{
    tb->tcg_llvm_context = nullptr;
    tb->llvm_function = nullptr;
}

void tcg_llvm_tb_free(TranslationBlock *tb)
{
    if(tb->llvm_function) {
        tb->llvm_function->eraseFromParent();
        tb->llvm_function = nullptr;
        tb->llvm_tc_ptr = nullptr;
        tb->llvm_tc_end = nullptr;
    }
}

const char* tcg_llvm_get_func_name(TranslationBlock *tb)
{
    if (tb->llvm_function) {
        return tb->llvm_function->getName().str().c_str();
    } else {
        return "";
    }
}

uintptr_t tcg_llvm_qemu_tb_exec(CPUArchState *env, TranslationBlock *tb)
{
    tcg_llvm_runtime.last_tb = tb;
    uintptr_t next_tb;
    next_tb = ((uintptr_t (*)(void*)) tb->llvm_tc_ptr)(env);
    return next_tb;
}

void tcg_llvm_write_module(TCGLLVMContext *l, const char *path)
{
    l->writeModule(path);
}

