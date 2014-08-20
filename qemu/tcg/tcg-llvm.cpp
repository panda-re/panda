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

extern "C" {
#include "tcg.h"
}

#include "tcg-llvm.h"
#include "panda_memlog.h"

extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "disas.h"

#include "panda_plugin.h"

#if defined(CONFIG_SOFTMMU)

#include "../../softmmu_defs.h"

// To support other architectures, make similar minor changes to op_helper.c
// These functions perform logging of dynamic values
#if (defined(TARGET_I386) || defined(TARGET_ARM))
static void *qemu_panda_ld_helpers[5] = {
    (void*) __ldb_mmu_panda,
    (void*) __ldw_mmu_panda,
    (void*) __ldl_mmu_panda,
    (void*) __ldq_mmu_panda,
    (void*) __ldq_mmu_panda,
};

static void *qemu_panda_st_helpers[5] = {
    (void*) __stb_mmu_panda,
    (void*) __stw_mmu_panda,
    (void*) __stl_mmu_panda,
    (void*) __stq_mmu_panda,
    (void*) __stq_mmu_panda,
};

static char *qemu_panda_ld_helper_names[5] = {
    (char*)"__ldb_mmu_panda",
    (char*)"__ldw_mmu_panda",
    (char*)"__ldl_mmu_panda",
    (char*)"__ldq_mmu_panda",
    (char*)"__ldq_mmu_panda",
};

static char *qemu_panda_st_helper_names[5] = {
    (char*)"__stb_mmu_panda",
    (char*)"__stw_mmu_panda",
    (char*)"__stl_mmu_panda",
    (char*)"__stq_mmu_panda",
    (char*)"__stq_mmu_panda",
};
#endif

static void *qemu_ld_helpers[5] = {
    (void*) __ldb_mmu,
    (void*) __ldw_mmu,
    (void*) __ldl_mmu,
    (void*) __ldq_mmu,
    (void*) __ldq_mmu,
};

static void *qemu_st_helpers[5] = {
    (void*) __stb_mmu,
    (void*) __stw_mmu,
    (void*) __stl_mmu,
    (void*) __stq_mmu,
    (void*) __stq_mmu,
};

static char *qemu_ld_helper_names[5] = {
    (char*)"__ldb_mmu",
    (char*)"__ldw_mmu",
    (char*)"__ldl_mmu",
    (char*)"__ldq_mmu",
    (char*)"__ldq_mmu",
};

static char *qemu_st_helper_names[5] = {
    (char*)"__stb_mmu",
    (char*)"__stw_mmu",
    (char*)"__stl_mmu",
    (char*)"__stq_mmu",
    (char*)"__stq_mmu",
};

#endif // CONFIG_SOFTMMU

}

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

//#undef NDEBUG

extern "C" {
    TCGLLVMContext* tcg_llvm_ctx = 0;

    /* These data is accessible from generated code */
    TCGLLVMRuntime tcg_llvm_runtime = {
        0, 0, {0,0,0}
        , 0, 0, 0
    };
}

extern CPUState *env;

using namespace llvm;

class TJITMemoryManager;

struct TCGLLVMContextPrivate {
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

    /* For reg-based globals, store argument number,
     * for mem-based globals, store base value index */
    int m_globalsIdx[TCG_MAX_TEMPS];

    BasicBlock* m_labels[TCG_MAX_LABELS];

public:
    TCGLLVMContextPrivate();
    ~TCGLLVMContextPrivate();

    void deleteExecutionEngine() {
        if (m_executionEngine) {
            delete m_executionEngine;
            m_executionEngine = NULL;
        }
    }

    FunctionPassManager *getFunctionPassManager() const {
        return m_functionPassManager;
    }

    /* Shortcuts */
    Type* intType(int w) { return IntegerType::get(m_context, w); }
    Type* intPtrType(int w) { return PointerType::get(intType(w), 0); }
    Type* wordType() { return intType(TCG_TARGET_REG_BITS); }
    Type* wordType(int bits) { return intType(bits); }
    Type* wordPtrType() { return intPtrType(TCG_TARGET_REG_BITS); }

    void adjustTypeSize(unsigned target, Value **v1) {
        Value *va = *v1;
        if (target == 32) {
            if (va->getType() == intType(64)) {
                *v1 = m_builder.CreateTrunc(va, intType(target));
            } else if (va->getType() != intType(32)) {
                assert(false);
            }
        }
    }

    void adjustTypeSize(unsigned target, Value **v1, Value **v2) {
        adjustTypeSize(target, v1);
        adjustTypeSize(target, v2);
    }

    Type* tcgType(int type) {
        return type == TCG_TYPE_I64 ? intType(64) : intType(32);
    }

    Type* tcgPtrType(int type) {
        return type == TCG_TYPE_I64 ? intPtrType(64) : intPtrType(32);
    }

    /* Helpers */
    Value* getValue(int idx);
    void setValue(int idx, Value *v);
    void delValue(int idx);

    Value* getPtrForValue(int idx);
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
    }

    BasicBlock* getLabel(int idx);
    void delLabel(int idx);
    void startNewBasicBlock(BasicBlock *bb = NULL);

    /* Code generation */
    Value* generateQemuMemOp(bool ld, Value *value, Value *addr,
                             int mem_index, int bits);
    void generateTraceCall(uintptr_t pc);
    int generateOperation(int opc, const TCGArg *args);
    void generateCode(TCGContext *s, TranslationBlock *tb);
};

/* Custom JITMemoryManager in order to capture the size of
 * the last generated function */
class TJITMemoryManager: public SectionMemoryManager {
    JITMemoryManager* m_base;
    ptrdiff_t m_lastFunctionSize;
public:
    TJITMemoryManager():
        m_base(JITMemoryManager::CreateDefaultMemManager()),
        m_lastFunctionSize(0) {}
    ~TJITMemoryManager() { delete m_base; }

    ptrdiff_t getLastFunctionSize() const { return m_lastFunctionSize; }

    uint8_t *startFunctionBody(const Function *F, uintptr_t &ActualSize) {
        m_lastFunctionSize = 0;
        return m_base->startFunctionBody(F, ActualSize);
    }
    void endFunctionBody(const Function *F, uint8_t *FunctionStart,
                                uint8_t *FunctionEnd) {
        m_lastFunctionSize = FunctionEnd - FunctionStart;
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
    }
    size_t GetDefaultStubSlabSize() {
        return m_base->GetDefaultStubSlabSize();
    }
    unsigned GetNumCodeSlabs() { return m_base->GetNumCodeSlabs(); }
    unsigned GetNumDataSlabs() { return m_base->GetNumDataSlabs(); }
    unsigned GetNumStubSlabs() { return m_base->GetNumStubSlabs(); }
};

TCGLLVMContextPrivate::TCGLLVMContextPrivate()
    : m_context(getGlobalContext()), m_builder(m_context), m_tbCount(0),
      m_tcgContext(NULL), m_tbFunction(NULL)
{
    std::memset(m_values, 0, sizeof(m_values));
    std::memset(m_memValuesPtr, 0, sizeof(m_memValuesPtr));
    std::memset(m_globalsIdx, 0, sizeof(m_globalsIdx));
    std::memset(m_labels, 0, sizeof(m_labels));

    InitializeNativeTarget();

    m_module = new Module("tcg-llvm", m_context);

    m_jitMemoryManager = new TJITMemoryManager();

    std::string error;

    /* Create JIT with optimization level set to none because some optimizations
     * (I think specifically, one dealing with simplifying CFGs) was messing up
     * our log processing.
     */
    m_executionEngine = ExecutionEngine::createJIT(
            m_module, &error, m_jitMemoryManager, CodeGenOpt::None);
    if(m_executionEngine == NULL) {
        std::cerr << "Unable to create LLVM JIT: " << error << std::endl;
        exit(1);
    }

    m_functionPassManager = new FunctionPassManager(m_module);
    m_functionPassManager->add(
            new DataLayout(*m_executionEngine->getDataLayout()));

    /* Try doing -O3 -Os: optimization level 3, with extra optimizations for
     * code size
     */
     //PassManagerBuilder PMBuilder;
     //PMBuilder.OptLevel = 2;
     //PMBuilder.SizeLevel = 2;
     //PMBuilder.populateFunctionPassManager(*m_functionPassManager);

    /*m_functionPassManager->add(createReassociatePass());
    m_functionPassManager->add(createConstantPropagationPass());
    m_functionPassManager->add(createInstructionCombiningPass());
    m_functionPassManager->add(createGVNPass());
    m_functionPassManager->add(createDeadStoreEliminationPass());
    m_functionPassManager->add(createCFGSimplificationPass());
    m_functionPassManager->add(createPromoteMemoryToRegisterPass());
    m_functionPassManager->add(createDeadInstEliminationPass());
    */

    //m_functionPassManager->add(new SelectRemovalPass());


    /* Note: another good place to look for optimization passes is in
     * clang/lib/CodeGen/BackendUtil.cpp
     */

    m_functionPassManager->doInitialization();
}

/* rwhelan: to restart LLVM again, there is either a bug with the
 * FunctionPassManager destructor not unregistering passes, or we need to
 * manually unregister our passes somehow.  If you don't add passes into LLVM,
 * then switching between TCG and LLVM should work fine.
 */
TCGLLVMContextPrivate::~TCGLLVMContextPrivate()
{
    if (m_functionPassManager){
        delete m_functionPassManager;
        m_functionPassManager = NULL;
    }

    // the following line will also delete
    // m_moduleProvider, m_module and all its functions
    if (m_executionEngine) {
        delete m_executionEngine;
        m_executionEngine = NULL;
    }

    if (llvm_is_multithreaded()){
        llvm_stop_multithreaded();
    }
}

Value* TCGLLVMContextPrivate::getPtrForValue(int idx)
{
    TCGContext *s = m_tcgContext;
    TCGTemp &temp = s->temps[idx];

    assert(idx < s->nb_globals || s->temps[idx].temp_local);

    if(m_memValuesPtr[idx] == NULL) {
        assert(idx < s->nb_globals);

        if(temp.fixed_reg) {
            Value *v = m_builder.CreateConstGEP1_32(
                    m_tbFunction->arg_begin(), m_globalsIdx[idx]);
            m_memValuesPtr[idx] = m_builder.CreatePointerCast(
                    v, tcgPtrType(temp.type)
                    , StringRef(temp.name) + "_ptr"
                    );

        } else {
            Value *v = getValue(m_globalsIdx[idx]);
            assert(v->getType() == wordType());

            v = m_builder.CreateAdd(v, ConstantInt::get(
                            wordType(), temp.mem_offset));
            m_memValuesPtr[idx] =
                m_builder.CreateIntToPtr(v, tcgPtrType(temp.type)
                        , StringRef(temp.name) + "_ptr"
                        );
        }
    }

    return m_memValuesPtr[idx];
}

inline void TCGLLVMContextPrivate::delValue(int idx)
{
    /* XXX
    if(m_values[idx] && m_values[idx]->use_empty()) {
        if(!isa<Instruction>(m_values[idx]) ||
                !cast<Instruction>(m_values[idx])->getParent())
            delete m_values[idx];
    }
    */
    m_values[idx] = NULL;
}

inline void TCGLLVMContextPrivate::delPtrForValue(int idx)
{
    /* XXX
    if(m_memValuesPtr[idx] && m_memValuesPtr[idx]->use_empty()) {
        if(!isa<Instruction>(m_memValuesPtr[idx]) ||
                !cast<Instruction>(m_memValuesPtr[idx])->getParent())
            delete m_memValuesPtr[idx];
    }
    */
    m_memValuesPtr[idx] = NULL;
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

    if(m_values[idx] == NULL) {
        if(idx < m_tcgContext->nb_globals) {
            m_values[idx] = m_builder.CreateLoad(getPtrForValue(idx)
                    , StringRef(m_tcgContext->temps[idx].name) + "_v"
                    );
        } else if(m_tcgContext->temps[idx].temp_local) {
            m_values[idx] = m_builder.CreateLoad(getPtrForValue(idx));
            std::ostringstream name;
            name << "loc" << (idx - m_tcgContext->nb_globals) << "_v";
            m_values[idx]->setName(name.str());
        } else {
            // Temp value was not previousely assigned
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
            m_globalsIdx[i] = s->temps[i].mem_reg;
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
            //std::ostringstream pName;
            //pName << "loc_" << (i - s->nb_globals) << "ptr";
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
    /* XXX
    if(m_labels[idx] && m_labels[idx]->use_empty() &&
            !m_labels[idx]->getParent())
        delete m_labels[idx];
    */
    m_labels[idx] = NULL;
}

void TCGLLVMContextPrivate::startNewBasicBlock(BasicBlock *bb)
{
    if(!bb)
        bb = BasicBlock::Create(m_context);
    else
        assert(bb->getParent() == 0);

    if(!m_builder.GetInsertBlock()->getTerminator()){
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
 * rwhelan: This now just calls the helper functions for whole system mode, and
 * we take care of the logging in there.  For user mode, we log in the IR.
 */
inline Value* TCGLLVMContextPrivate::generateQemuMemOp(bool ld,
        Value *value, Value *addr, int mem_index, int bits)
{
    assert(addr->getType() == intType(TARGET_LONG_BITS));
    assert(ld || value->getType() == intType(bits));
    assert(TCG_TARGET_REG_BITS == 64); //XXX

#ifdef CONFIG_SOFTMMU

    uintptr_t helperFuncAddr;

    if (panda_use_memcb){
        helperFuncAddr = ld ? (uint64_t) qemu_panda_ld_helpers[bits>>4]:
                               (uint64_t) qemu_panda_st_helpers[bits>>4];
    }
    else {
        helperFuncAddr = ld ? (uint64_t) qemu_ld_helpers[bits>>4]:
                               (uint64_t) qemu_st_helpers[bits>>4];
    }

    std::vector<Value*> argValues;
    argValues.reserve(3);
    argValues.push_back(addr);
    if(!ld)
        argValues.push_back(value);
    argValues.push_back(ConstantInt::get(intType(8*sizeof(int)), mem_index));

    std::vector<Type*> argTypes;
    argTypes.reserve(3);
    for(int i=0; i<(ld?2:3); ++i)
        argTypes.push_back(argValues[i]->getType());

    FunctionType* helperFunctionTy;
    if (ld){
        helperFunctionTy = FunctionType::get(intType(bits),
            argTypes, false);
    } else {
        helperFunctionTy = FunctionType::get(Type::getVoidTy(m_context),
            argTypes, false);
    }

    char *funcName;
    if (panda_use_memcb){
        funcName = ld ? qemu_panda_ld_helper_names[bits>>4]:
            qemu_panda_st_helper_names[bits>>4];
    }
    else {
        funcName = ld ? qemu_ld_helper_names[bits>>4]:
            qemu_st_helper_names[bits>>4];
    }
    assert(funcName);
    Function* helperFunction = m_module->getFunction(funcName);
    if(!helperFunction) {
        helperFunction = Function::Create(
                helperFunctionTy,
                Function::ExternalLinkage, funcName, m_module);
        m_executionEngine->addGlobalMapping(helperFunction,
                                            (void*) helperFuncAddr);
    }

    return m_builder.CreateCall(helperFunction, ArrayRef<Value*>(argValues));


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
        return NULL;
    }
#endif // CONFIG_SOFTMMU
}

int TCGLLVMContextPrivate::generateOperation(int opc, const TCGArg *args)
{
    Value *v;
    TCGOpDef &def = tcg_op_defs[opc];
    int nb_args = def.nb_args;

    switch(opc) {
    case INDEX_op_debug_insn_start:
        break;

    /* predefined ops */
    case INDEX_op_nop:
    case INDEX_op_nop1:
    case INDEX_op_nop2:
    case INDEX_op_nop3:
        break;

    case INDEX_op_nopn:
        nb_args = args[0];
        break;

    case INDEX_op_discard:
        delValue(args[0]);
        break;

    case INDEX_op_call:
        {
            int nb_oargs = args[0] >> 16;
            int nb_iargs = args[0] & 0xffff;
            nb_args = nb_oargs + nb_iargs + def.nb_cargs + 1;

            //int flags = args[nb_oargs + nb_iargs + 1];
            //assert((flags & TCG_CALL_TYPE_MASK) == TCG_CALL_TYPE_STD);

            std::vector<Value*> argValues;
            std::vector<Type*> argTypes;
            argValues.reserve(nb_iargs-1);
            argTypes.reserve(nb_iargs-1);
            for(int i=0; i < nb_iargs-1; ++i) {
                TCGArg arg = args[nb_oargs + i + 1];
                if(arg != TCG_CALL_DUMMY_ARG) {
                    Value *v = getValue(arg);
                    argValues.push_back(v);
                    argTypes.push_back(v->getType());
                }
            }

            assert(nb_oargs == 0 || nb_oargs == 1);
            Type* retType = nb_oargs == 0 ?
                Type::getVoidTy(m_context) : wordType(getValueBits(args[1]));

            Value* helperAddr = getValue(args[nb_oargs + nb_iargs]);
            Value* result;

            tcg_target_ulong helperAddrC = (tcg_target_ulong)
                   cast<ConstantInt>(helperAddr)->getZExtValue();

            const char *helperName = tcg_helper_get_name(m_tcgContext,
                                                         (void*) helperAddrC);
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

            if(nb_oargs == 1)
                setValue(args[1], result);

        }
        break;

    case INDEX_op_br:
        m_builder.CreateBr(getLabel(args[0]));
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
        m_builder.CreateCondBr(v, getLabel(args[3]), bb);           \
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

#define __OP_SETCOND(opc_name, bits)                                \
    case opc_name: {                                                \
        Value* retptr = getPtrForValue(args[0]);                    \
        Value* ret = m_builder.CreateLoad(retptr);                  \
        Value* v1  = getValue(args[1]);                             \
        Value* v2  = getValue(args[2]);                             \
        assert(ret->getType() == intType(bits));                    \
        assert(v1->getType() == intType(bits));                     \
        assert(v2->getType() == intType(bits));                     \
        switch(args[3]) {                                           \
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
        BasicBlock* bb = BasicBlock::Create(m_context, "setZero");  \
        BasicBlock* finished = BasicBlock::Create(m_context, "done");\
        BasicBlock* bbSet = BasicBlock::Create(m_context, "setOne");\
        m_builder.CreateCondBr(v, bbSet, bb);                       \
        m_tbFunction->getBasicBlockList().push_back(bbSet);         \
        m_builder.SetInsertPoint(bbSet);                            \
        setValue(args[0], ConstantInt::get(intType(bits), 1));      \
        delValue(args[0]);                                          \
        m_builder.CreateBr(finished);                               \
        m_tbFunction->getBasicBlockList().push_back(bb);            \
        m_builder.SetInsertPoint(bb);                               \
        setValue(args[0], ConstantInt::get(intType(bits), 0));      \
        delValue(args[0]);                                          \
        m_builder.CreateBr(finished);                               \
        m_tbFunction->getBasicBlockList().push_back(finished);      \
        m_builder.SetInsertPoint(finished);                         \
    } break;

    __OP_SETCOND(INDEX_op_setcond_i32, 32)

#if TCG_TARGET_REG_BITS == 64
    __OP_SETCOND(INDEX_op_setcond_i64, 64)
#endif

#undef __OP_SETCOND_C
#undef __OP_SETCOND

    case INDEX_op_set_label:
        assert(getLabel(args[0])->getParent() == 0);
        startNewBasicBlock(getLabel(args[0]));
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
    case opc_name:                                                  \
        assert(getValue(args[1])->getType() == wordType());         \
        v = m_builder.CreateAdd(getValue(args[1]),                  \
                    ConstantInt::get(wordType(), args[2]));         \
        v = m_builder.CreateIntToPtr(v, intPtrType(memBits));       \
        v = m_builder.CreateLoad(v);                                \
        setValue(args[0], m_builder.Create ## signE ## Ext(         \
                    v, intType(regBits)));                          \
        break;

#define __ST_OP(opc_name, memBits, regBits)                         \
    case opc_name:  {                                                 \
        assert(getValue(args[0])->getType() == intType(regBits));   \
        assert(getValue(args[1])->getType() == wordType());         \
        Value* valueToStore = getValue(args[0]);                    \
                                                                    \
                                                                    \
        v = m_builder.CreateAdd(getValue(args[1]),                  \
                    ConstantInt::get(wordType(), args[2]));         \
        v = m_builder.CreateIntToPtr(v, intPtrType(memBits));       \
        m_builder.CreateStore(m_builder.CreateTrunc(                \
                valueToStore, intType(memBits)), v);           \
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

#define __ARITH_OP_DIV2(opc_name, signE, bits)                      \
    case opc_name:                                                  \
        assert(getValue(args[2])->getType() == intType(bits));      \
        assert(getValue(args[3])->getType() == intType(bits));      \
        assert(getValue(args[4])->getType() == intType(bits));      \
        v = m_builder.CreateShl(                                    \
                m_builder.CreateZExt(                               \
                    getValue(args[3]), intType(bits*2)),            \
                m_builder.CreateZExt(                               \
                    ConstantInt::get(intType(bits), bits),          \
                    intType(bits*2)));                              \
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
        Type* Tys[] = { intType(sBits) };                     \
        Function *bswap = Intrinsic::getDeclaration(m_module,       \
                Intrinsic::bswap, ArrayRef<Type*>(Tys,1));                          \
        v = m_builder.CreateTrunc(getValue(args[1]),intType(sBits));\
        setValue(args[0], m_builder.CreateZExt(                     \
                m_builder.CreateCall(bswap, v), intType(bits)));    \
        } break;


    __ARITH_OP(INDEX_op_add_i32, Add, 32)
    __ARITH_OP(INDEX_op_sub_i32, Sub, 32)
    __ARITH_OP(INDEX_op_mul_i32, Mul, 32)

#ifdef TCG_TARGET_HAS_div_i32
    __ARITH_OP(INDEX_op_div_i32,  SDiv, 32)
    __ARITH_OP(INDEX_op_divu_i32, UDiv, 32)
    __ARITH_OP(INDEX_op_rem_i32,  SRem, 32)
    __ARITH_OP(INDEX_op_remu_i32, URem, 32)
#else
    __ARITH_OP_DIV2(INDEX_op_div2_i32,  S, 32)
    __ARITH_OP_DIV2(INDEX_op_divu2_i32, U, 32)
#endif

    __ARITH_OP(INDEX_op_and_i32, And, 32)
    __ARITH_OP(INDEX_op_or_i32,   Or, 32)
    __ARITH_OP(INDEX_op_xor_i32, Xor, 32)

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

    /* QEMU specific */
#if TCG_TARGET_REG_BITS == 64

#define __OP_QEMU_ST(opc_name, bits)                                \
    case opc_name:                                                  \
        generateQemuMemOp(false,                                    \
            m_builder.CreateIntCast(                                \
                getValue(args[0]), intType(bits), false),           \
            getValue(args[1]), args[2], bits);                      \
        break;


#define __OP_QEMU_LD(opc_name, bits, signE)                         \
    case opc_name:                                                  \
        v = generateQemuMemOp(true, NULL,                           \
            getValue(args[1]), args[2], bits);                      \
        setValue(args[0], m_builder.Create ## signE ## Ext(         \
            v, intType(std::max(TARGET_LONG_BITS, bits))));         \
        break;

#define __OP_QEMU_LDD(opc_name, bits)                               \
    case opc_name:                                                  \
        v = generateQemuMemOp(true, NULL,                           \
            getValue(args[1]), args[2], bits);                      \
        setValue(args[0], v);         \
        break;

    __OP_QEMU_ST(INDEX_op_qemu_st8,   8)
    __OP_QEMU_ST(INDEX_op_qemu_st16, 16)
    __OP_QEMU_ST(INDEX_op_qemu_st32, 32)
    __OP_QEMU_ST(INDEX_op_qemu_st64, 64)

    __OP_QEMU_LD(INDEX_op_qemu_ld8s,   8, S)
    __OP_QEMU_LD(INDEX_op_qemu_ld8u,   8, Z)
    __OP_QEMU_LD(INDEX_op_qemu_ld16s, 16, S)
    __OP_QEMU_LD(INDEX_op_qemu_ld16u, 16, Z)
    __OP_QEMU_LD(INDEX_op_qemu_ld32s, 32, S)
    __OP_QEMU_LD(INDEX_op_qemu_ld32u, 32, Z)
    __OP_QEMU_LD(INDEX_op_qemu_ld64,  64, Z)

    __OP_QEMU_LDD(INDEX_op_qemu_ld32, 32)

#undef __OP_QEMU_LD
#undef __OP_QEMU_ST
#undef __OP_QEMU_LDD

#endif

    case INDEX_op_exit_tb:
        m_builder.CreateRet(ConstantInt::get(wordType(), args[0]));
        break;

    case INDEX_op_goto_tb:
        /* XXX: tb linking is disabled */
        break;

    case INDEX_op_deposit_i32: {
        //llvm::errs() << *m_tbFunction << "\n";
        Value *arg1 = getValue(args[1]);
        //llvm::errs() << "arg1=" << *arg1 << "\n";
        //arg1 = m_builder.CreateTrunc(arg1, intType(32));


        Value *arg2 = getValue(args[2]);
        //llvm::errs() << "arg2=" << *arg2 << "\n";
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
        //llvm::errs() << *m_tbFunction << "\n";
        Value *arg1 = getValue(args[1]);
        //llvm::errs() << "arg1=" << *arg1 << "\n";
        //arg1 = m_builder.CreateTrunc(arg1, intType(32));


        Value *arg2 = getValue(args[2]);
        //llvm::errs() << "arg2=" << *arg2 << "\n";
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

    FunctionType *tbFunctionType = FunctionType::get(
            wordType(),
            std::vector<Type*>(1, intPtrType(64)), false);
    m_tbFunction = Function::Create(tbFunctionType,
            Function::PrivateLinkage, fName.str(), m_module);
    BasicBlock *basicBlock = BasicBlock::Create(m_context,
            "entry", m_tbFunction);
    m_builder.SetInsertPoint(basicBlock);

    m_tcgContext = s;

    /* Prepare globals and temps information */
    initGlobalsAndLocalTemps();

    /* Generate code for each opc */
    const TCGArg *args = gen_opparam_buf;
    for(int opc_index=0; ;++opc_index) {
        int opc = gen_opc_buf[opc_index];

        if(opc == INDEX_op_end)
            break;

        if(opc == INDEX_op_debug_insn_start) {
            // volatile store of current OPC index
            m_builder.CreateStore(ConstantInt::get(wordType(), opc_index),
                m_builder.CreateIntToPtr(
                    ConstantInt::get(wordType(),
                        (uint64_t) &tcg_llvm_runtime.last_opc_index),
                    wordPtrType()),
                true);
            // volatile store of current PC
	    llvm::Instruction *i = 
	      m_builder.CreateStore(ConstantInt::get(wordType(), args[0]),
                m_builder.CreateIntToPtr(
                    ConstantInt::get(wordType(),
                        (uint64_t) &tcg_llvm_runtime.last_pc),
                    wordPtrType()),
                true);	    
	    // TRL 2014 hack to annotate that last instruction as the one
	    // that sets PC
	    LLVMContext& C = i->getContext();
	    MDNode* N = MDNode::get(C, MDString::get(C, "pcupdate"));
	    i->setMetadata("pcupdate.md", N);
        }

        args += generateOperation(opc, args);
        //llvm::errs() << *m_tbFunction << "\n";
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

    // run all specified function passes
    m_functionPassManager->run(*m_tbFunction);

//#ifndef NDEBUG
    verifyFunction(*m_tbFunction);
//#endif

    tb->llvm_function = m_tbFunction;

    if(execute_llvm || qemu_loglevel_mask(CPU_LOG_LLVM_ASM)) {
        tb->llvm_tc_ptr = (uint8_t*)
                m_executionEngine->getPointerToFunction(m_tbFunction);
        tb->llvm_tc_end = tb->llvm_tc_ptr +
                m_jitMemoryManager->getLastFunctionSize();
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
    assert(tb->tcg_llvm_context == NULL);
    assert(tb->llvm_function == NULL);

    tb->tcg_llvm_context = this;
    m_private->generateCode(s, tb);
}

void TCGLLVMContext::writeModule(char *path){
    std::string Error;
    raw_ostream *outfile;
    outfile = new raw_fd_ostream(path, Error,
        raw_fd_ostream::F_Binary);
    std::string err;
    if (verifyModule(*getModule(), llvm::PrintMessageAction, &err)){
        printf("%s\n", err.c_str());
        exit(1);
    }
    WriteBitcodeToFile(getModule(), *outfile);
    delete outfile;
}

/*****************************/
/* Functions for QEMU c code */

TCGLLVMContext* tcg_llvm_initialize()
{
    if (!llvm_start_multithreaded()) {
        fprintf(stderr, "Could not initialize LLVM threading\n");
        exit(-1);
    }
    return new TCGLLVMContext;
}

void tcg_llvm_destroy(){
    if (tcg_llvm_ctx){
        delete tcg_llvm_ctx;
        tcg_llvm_ctx = NULL;
    }
}

void tcg_llvm_gen_code(TCGLLVMContext *l, TCGContext *s, TranslationBlock *tb)
{
    l->generateCode(s, tb);
}

void tcg_llvm_tb_alloc(TranslationBlock *tb)
{
    tb->tcg_llvm_context = NULL;
    tb->llvm_function = NULL;
}

void tcg_llvm_tb_free(TranslationBlock *tb)
{
    if(tb->llvm_function) {
        tb->llvm_function->eraseFromParent();
        tb->llvm_function = NULL;
        tb->llvm_tc_ptr = NULL;
    }
}

int tcg_llvm_search_last_pc(TranslationBlock *tb, uintptr_t searched_pc)
{
    assert(tb->llvm_function && tb == tcg_llvm_runtime.last_tb);
    return tcg_llvm_runtime.last_opc_index;
}

const char* tcg_llvm_get_func_name(TranslationBlock *tb)
{
    static char buf[500];
    if(tb->llvm_function) {
        strncpy(buf, tb->llvm_function->getName().str().c_str(), sizeof(buf));
    } else {
        buf[0] = 0;
    }
    return buf;
}

#ifdef CONFIG_LLVM
extern CPUState *env;
#endif

uintptr_t tcg_llvm_qemu_tb_exec(void *env1, TranslationBlock *tb)
{
    tcg_llvm_runtime.last_tb = tb;
    env = (CPUState*)env1;
    uintptr_t next_tb;
    next_tb = ((uintptr_t (*)(void*)) tb->llvm_tc_ptr)(&env);
    return next_tb;
}

void tcg_llvm_write_module(TCGLLVMContext *l, char *path){
    l->writeModule(path);
}

