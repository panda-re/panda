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

#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/Threading.h>

#include <llvm/Support/DynamicLibrary.h>
#include <llvm/Support/raw_ostream.h>

#include <llvm/ExecutionEngine/Orc/RTDyldObjectLinkingLayer.h>

#include <iostream>
#include <sstream>
#include <map>

#include "panda/cheaders.h"
#include "panda/tcg-llvm.h"
#include "panda/helper_runtime.h"

#if defined(CONFIG_SOFTMMU)

// To support other architectures, make similar minor changes to op_helper.c
static const char *qemu_ld_helper_names[16];
static const char *qemu_st_helper_names[16];

#endif // CONFIG_SOFTMMU

extern "C" {
    TCGLLVMTranslator *tcg_llvm_translator = nullptr;

    /* This data is accessible from generated code */
    TCGLLVMRuntime tcg_llvm_runtime = {};

    /* the TB whose host assembly size still needs to be determined */
    static struct TranslationBlock *pending_tb;
    static bool need_section_size = false;
    static uint64_t section_size = 0;
}

extern CPUState *env;

using namespace llvm;

/*
 * This callback is executed just after the host assembly code corresponding to
 * an LLVM function is generated.  We need to extract the number of bytes in the
 * generated code (aka the section size) for use in the associated
 * TranslationBlock.
 */
void getLLVMAssemblySize(orc::VModuleKey,
        const object::ObjectFile &obj,
        const RuntimeDyld::LoadedObjectInfo &objInfo) {
    if (!need_section_size) {
        return;
    }
    /*
     * There are multiple symbols associated with the just JITted code.  One of
     * them has the same name as the LLVM function currently being processed.
     */
    for (object::symbol_iterator cur_sym = obj.symbol_begin(),
            end_sym = obj.symbol_end(); cur_sym != end_sym; ++cur_sym) {
        if (cur_sym->getFlags()) {
            /* don't waste time with undefined symbols */
            uint32_t flags = cur_sym->getFlags().get();
            if (flags & object::SymbolRef::SF_Undefined) {
                continue;
            }
        } else {
            /* flags indicate an error, hopefully not important */
            std::cerr << "Error getting symbol flags" << std::endl;
            continue;
        }

        /* is this the symbol for the LLVM function currently being JITted? */
        StringRef name;
        if (auto name_or_err = cur_sym->getName()) {
            name = *name_or_err;
        } else {
            /* hopefully it's not the one we want, and can just continue */
            std::cerr << "Could not get section name" << std::endl;
            continue;
        }
        if (0 == name.str().find(pending_tb->llvm_fn_name)) {
            object::section_iterator sec_it = obj.section_end();
            if (auto si_or_err = cur_sym->getSection()) {
                sec_it = *si_or_err;
                // save section size so can calculate end after have start
                section_size = (*sec_it).getSize();
                need_section_size = false;
                break;
            } else {
                std::cerr << "Error getting section for " <<
                        pending_tb->llvm_fn_name << std::endl;
                assert(false);
            }
        }
    }
}

TCGLLVMTranslator::TCGLLVMTranslator()
    : m_builder(*m_context), m_tbCount(0), m_tcgContext(NULL),
      m_tbFunction(NULL), m_tbType(NULL) {

    std::memset(m_labels, 0, sizeof(m_labels));
    std::memset(m_values, 0, sizeof(m_values));
    std::memset(m_memValuesPtr, 0, sizeof(m_memValuesPtr));
    std::memset(m_globalsIdx, 0, sizeof(m_globalsIdx));

    initMemoryHelpers();
    m_cpuType = NULL;
    m_cpuState = NULL;
    m_eip = NULL;
    m_ccop = NULL;

    m_functionPassManager = new legacy::FunctionPassManager(m_module.get());

    /*
    Note: if we want to use any of these, they also need to get added to the
    function pass manager that is created in jitPendingModule().

    m_functionPassManager->add(createReassociatePass());
    m_functionPassManager->add(createConstantPropagationPass());
    m_functionPassManager->add(createInstructionCombiningPass());
    m_functionPassManager->add(createGVNPass());
    m_functionPassManager->add(createDeadStoreEliminationPass());
    m_functionPassManager->add(createCFGSimplificationPass());
    m_functionPassManager->add(createPromoteMemoryToRegisterPass());
    */

#define XSTR(x) STR(x)
#define STR(x) #x
    m_CPUArchStateName = XSTR(CPUArchState);
    m_CPUArchStateName[6] = '.'; // Replace space with dot.
#undef STR
#undef XSTR

    jit->getMainJITDylib().addGenerator(cantFail(
        orc::DynamicLibrarySearchGenerator::GetForCurrentProcess(
        DL.getGlobalPrefix())));

    orc::RTDyldObjectLinkingLayer::NotifyLoadedFunction notify_loaded_fn =
            getLLVMAssemblySize;
    static_cast<orc::RTDyldObjectLinkingLayer&>(
            jit->getObjLinkingLayer()).setNotifyLoaded(notify_loaded_fn);
}

void TCGLLVMTranslator::adjustTypeSize(unsigned target, Value **v1) {
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

void TCGLLVMTranslator::initMemoryHelpers() {
    qemu_ld_helper_names[MO_UB] = "helper_ret_ldub_mmu_panda";
    qemu_ld_helper_names[MO_LEUW] = "helper_le_lduw_mmu_panda";
    qemu_ld_helper_names[MO_LEUL] = "helper_le_ldul_mmu_panda";
    qemu_ld_helper_names[MO_LEQ] = "helper_le_ldq_mmu_panda";
    qemu_ld_helper_names[MO_BEUW] = "helper_be_lduw_mmu_panda";
    qemu_ld_helper_names[MO_BEUL] = "helper_be_ldul_mmu_panda";
    qemu_ld_helper_names[MO_BEQ] = "helper_be_ldq_mmu_panda";
    qemu_st_helper_names[MO_UB] = "helper_ret_stb_mmu_panda";
    qemu_st_helper_names[MO_LEUW] = "helper_le_stw_mmu_panda";
    qemu_st_helper_names[MO_LEUL] = "helper_le_stl_mmu_panda";
    qemu_st_helper_names[MO_LEQ] = "helper_le_stq_mmu_panda";
    qemu_st_helper_names[MO_BEUW] = "helper_be_stw_mmu_panda";
    qemu_st_helper_names[MO_BEUL] = "helper_be_stl_mmu_panda";
    qemu_st_helper_names[MO_BEQ] = "helper_be_stq_mmu_panda";
}

Value *TCGLLVMTranslator::getPtrForValue(int idx)
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

    if(m_memValuesPtr[idx] == NULL) {
        assert(idx < s->nb_globals);

        if(temp.fixed_reg) {
            assert(false);
        } else {
            Value *v = m_builder.CreateAdd(m_envInt,
                    constWord(temp.mem_offset));
            m_memValuesPtr[idx] = m_builder.CreateIntToPtr(
                    v, tcgPtrType(temp.type),
                    StringRef(temp.name) + "_ptr");
        }
    }

    return m_memValuesPtr[idx];
}

Value* TCGLLVMTranslator::getEnvOffsetPtr(int64_t offset, TCGTemp &temp) {
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

        Value *v = m_builder.CreateAdd(m_envInt, constWord(offset));
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
        if(!isa<Instruction>(V) || !cast<Instruction>(V)->getParent()) {
            V->deleteValue();
        }
    }
}

inline void TCGLLVMTranslator::delValue(int idx)
{
    assert(idx >= 0 && idx < TCG_MAX_TEMPS);
    freeValue(m_values[idx]);
    m_values[idx] = nullptr;
}

inline void TCGLLVMTranslator::delPtrForValue(int idx)
{
    assert(idx >= 0 && idx < TCG_MAX_TEMPS);
    freeValue(m_memValuesPtr[idx]);
    m_memValuesPtr[idx] = nullptr;
}

unsigned TCGLLVMTranslator::getValueBits(int idx)
{
    assert(idx >= 0 && idx < TCG_MAX_TEMPS);

    switch (m_tcgContext->temps[idx].type) {
        case TCG_TYPE_I32: return 32;
        case TCG_TYPE_I64: return 64;
        default: assert(false && "Unknown size");
    }
    return 0;
}

Value *TCGLLVMTranslator::getValue(int idx)
{
    assert(idx >= 0 && idx < TCG_MAX_TEMPS);

    const TCGTemp &temp = m_tcgContext->temps[idx];

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

void TCGLLVMTranslator::setValue(int idx, Value *v)
{
    assert(idx >= 0 && idx < TCG_MAX_TEMPS);

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

void TCGLLVMTranslator::initGlobalsAndLocalTemps()
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
                tcgType(s->temps[i].type), nullptr/*, pName.str()*/);
        }
    }
}

inline BasicBlock *TCGLLVMTranslator::getLabel(int idx)
{
    if(!m_labels[idx]) {
        //std::ostringstream bbName;
        //bbName << "label_" << idx;
        m_labels[idx] = BasicBlock::Create(*m_context/*, bbName.str()*/);
    }
    return m_labels[idx];
}

void TCGLLVMTranslator::startNewBasicBlock(BasicBlock *bb)
{
    if(!bb) {
        bb = BasicBlock::Create(*m_context);
    } else {
        assert(bb->getParent() == 0);
    }

    if(!m_builder.GetInsertBlock()->getTerminator()) {
        m_builder.CreateBr(bb);
    }

    m_tbFunction->getBasicBlockList().push_back(bb);
    m_builder.SetInsertPoint(bb);

    /* Invalidate all temps */
    for(int i=0; i<TCG_MAX_TEMPS; ++i) {
        delValue(i);
    }

    /* Invalidate all pointers to globals */
    for(int i=0; i<m_tcgContext->nb_globals; ++i) {
        delPtrForValue(i);
    }
}

/*
 * rwhelan: This now just calls the helper functions for whole system mode, and
 * we take care of the logging in there.  For user mode, we log in the IR.
 */
inline Value *TCGLLVMTranslator::generateQemuMemOp(bool ld,
        Value *value, Value *addr, int flags, int mem_index, int bits, uintptr_t ret_addr) {

    assert(addr->getType() == intType(TARGET_LONG_BITS));
    assert(ld || value->getType() == intType(bits));

#if TCG_TARGET_REG_BITS != 64
#error "FIXME: Can't compile PANDA LLVM backend on 32-bit host machine."
#endif

#ifdef CONFIG_SOFTMMU
    TCGMemOp opc = get_memop(flags);
    const int memIdx = opc & (MO_BSWAP | MO_SIZE);
    const int numArgs = ld ? 4 : 5;

    std::vector<Value*> argValues;
    argValues.reserve(numArgs);
    argValues.push_back(getEnv());
    argValues.push_back(addr);
    if(!ld) {
        argValues.push_back(value);
    }
    argValues.push_back(constInt(8*sizeof(int), mem_index));
    argValues.push_back(constInt(8*sizeof(uintptr_t), ret_addr));

    const char *funcName;
    funcName = ld ? qemu_ld_helper_names[memIdx] : qemu_st_helper_names[memIdx];
    assert(funcName);

    Function *helperFunction = m_module->getFunction(funcName);
    if(!helperFunction) {

        std::vector<llvm::Type*> argTypes;
        argTypes.reserve(numArgs);
        for(int i=0; i<numArgs; ++i) {
            argTypes.push_back(argValues[i]->getType());
        }

        FunctionType* helperFunctionTy;
        if (ld) {
            int retBits;
            // Load helpers return i64 except for bytes, which return i8.
            switch (opc & MO_SSIZE) {
                case MO_SB:
                case MO_UB:
                    retBits = 8;
                    break;
                default:
                    retBits = 64;
                    break;
            }
            helperFunctionTy = FunctionType::get(intType(retBits), argTypes,
                false);
        } else {
            helperFunctionTy = FunctionType::get(
                llvm::Type::getVoidTy(*m_context), argTypes, false);
        }

        helperFunction = Function::Create(helperFunctionTy,
            Function::ExternalLinkage, funcName, m_module.get());
    }

    Value *loadedValue = m_builder.CreateCall(helperFunction,
        ArrayRef<Value*>(argValues));
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
    addr = m_builder.CreateAdd(addr, constWord(GUEST_BASE));
    addr = m_builder.CreateIntToPtr(addr, intPtrType(bits));
    if(ld) {
        return m_builder.CreateLoad(addr);
    } else {
        m_builder.CreateStore(value, addr);
        return nullptr;
    }
#endif // CONFIG_SOFTMMU
}

int TCGLLVMTranslator::generateOperation(int opc, const TCGOp *op,
    const TCGArg *args) {
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
                llvm::Type::getVoidTy(*m_context) : intType(getValueBits(args[0]));

            Value* helperAddr = constInt(sizeof(uintptr_t)*8,
                args[nb_oargs + nb_iargs]);
            Value* result;

            tcg_target_ulong helperAddrC = (tcg_target_ulong)
                   cast<ConstantInt>(helperAddr)->getZExtValue();

            const char *helperName = tcg_find_helper(m_tcgContext,
                                                     (uintptr_t)helperAddrC);
            FunctionType *ft = FunctionType::get(retType, argTypes, false);
            Value *callTarget = NULL;
            if (!helperName) {
                // In this case, we couldn't find a helper. All we know is that
                // this is a function poiner.
                PointerType *fpt = PointerType::getUnqual(ft);
                assert(fpt);
                Value *pointerValue = m_builder.getInt64(helperAddrC);
                assert(pointerValue);
                callTarget = m_builder.CreateIntToPtr(pointerValue, fpt);
                assert(callTarget);
            } else {
                std::string funcName = std::string("helper_") + helperName;
                callTarget = m_module->getFunction(funcName);
                if(!callTarget) {
                    callTarget = Function::Create(ft,
                        Function::ExternalLinkage, funcName, m_module.get());
                }
            }

            result = m_builder.CreateCall(
                cast<FunctionType>(callTarget->getType()->getPointerElementType()),
                callTarget, ArrayRef<Value*>(argValues));

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
        BasicBlock* bb = BasicBlock::Create(*m_context);            \
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
        setValue(args[0], constInt(32, args[1]));
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
        setValue(args[0], constInt(64, args[1]));
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
                m_builder.CreateZExt(                               \
                    constInt(bits, bits),                           \
                    intType(bits * 2)));                            \
        v = m_builder.CreateOr(v,                                   \
                m_builder.CreateZExt(                               \
                    getValue(args[2]), intType(bits*2)));           \
        setValue(args[0], m_builder.CreateTrunc(                    \
                m_builder.Create ## signE ## Div(                   \
                v, m_builder.CreateZExt(                            \
                        getValue(args[4]), intType(bits*2))         \
                ),                                                  \
                intType(bits)));                                    \
        setValue(args[1], m_builder.CreateTrunc(                    \
                m_builder.Create ## signE ## Rem(                   \
                v, m_builder.CreateZExt(                            \
                        getValue(args[4]), intType(bits*2))         \
                        ),                                          \
                        intType(bits)));                            \
        break;

#define __ARITH_OP_ROT(opc_name, op1, op2, bits)                    \
    case opc_name:                                                  \
        assert(getValue(args[1])->getType() == intType(bits));      \
        assert(getValue(args[2])->getType() == intType(bits));      \
        v = m_builder.CreateSub(                                    \
                constInt(bits, bits),                               \
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
                    constInt(bits, i),                              \
                    getValue(args[1])));                            \
        break;

#define __ARITH_OP_BSWAP(opc_name, sBits, bits)                     \
    case opc_name: {                                                \
        assert(getValue(args[1])->getType() == intType(bits));      \
        llvm::Type* Tys[] = { intType(sBits) };                     \
        Function *bswap = Intrinsic::getDeclaration(m_module.get(), \
                Intrinsic::bswap, ArrayRef<llvm::Type*>(Tys,1));    \
        v = m_builder.CreateTrunc(getValue(args[1]),intType(sBits));\
        setValue(args[0], m_builder.CreateZExt(                     \
                m_builder.CreateCall(bswap, v), intType(bits)));    \
        } break;

    /* for ops of type op out_lo, out_hi, in, in */
#define __ARITH_OP_DECOMPOSE(opc_name, op, extend, bits)            \
    case opc_name: {                                                \
        assert(getValue(args[2])->getType() == intType(bits));      \
        assert(getValue(args[3])->getType() == intType(bits));      \
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
                bits);                                                 \
        Value *first_arg = m_builder.CreateOr(ext1, ext2);             \
        Value *ext3 = m_builder.CreateZExt(                            \
                getValue(args[4]), intType(bits*2));                   \
        Value *ext4 = m_builder.CreateShl(                             \
                m_builder.CreateZExt(                                  \
                    getValue(args[5]), intType(bits*2)),               \
                bits);                                                 \
        Value *second_arg = m_builder.CreateOr(ext3, ext4);            \
        Value *full = m_builder.Create ## op(first_arg, second_arg);   \
        setValue(args[0], m_builder.CreateTrunc(                       \
                    full, intType(bits)));                             \
        setValue(args[1], m_builder.CreateTrunc(                       \
                    m_builder.CreateLShr(full, bits),                  \
                    intType(bits)));                                   \
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
        m_builder.CreateRet(constWord(args[0]));
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
        Function *intrinsic = Intrinsic::getDeclaration(m_module.get(),
                intrinsicID, ArrayRef<llvm::Type*>(Tys, 1));
        // declare i32  @llvm.ctlz.i32 (i32  <src>, i1 <is_zero_undef>)
        Value* callArgs[] = { source, constInt(1, false) };
        Value *result = m_builder.CreateCall(intrinsic,
                ArrayRef<Value*>(callArgs, 2));
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

void TCGLLVMTranslator::checkAndLogLLVMIR()
{
    if(qemu_loglevel_mask(CPU_LOG_LLVM_IR)) {
        std::string fcnString;
        raw_string_ostream ss(fcnString);
        ss << *m_tbFunction;
        qemu_log("OUT (LLVM IR):\n");
        qemu_log("%s", ss.str().c_str());
        qemu_log("\n");
        qemu_log_flush();
    }
}

// Add m_module to JIT
// Create new module for next block
void TCGLLVMTranslator::jitPendingModule()
{
    if(jit->addLazyIRModule(orc::ThreadSafeModule(
            std::move(m_module), m_tsc))) {
        std::cerr << "Cannot add module to JIT" << std::endl;
        assert(false);
    }

    m_module = std::make_unique<Module>(("tcg-llvm" +
        std::to_string(m_tbCount)).c_str(), *m_context);
    m_functionPassManager = new legacy::FunctionPassManager(m_module.get());
    for(auto cb : newModuleCallbacks) {
        cb(m_module.get(), m_functionPassManager);
    }
}


void TCGLLVMTranslator::generateCode(TCGContext *s, TranslationBlock *tb)
{
    assert(tb->llvm_tc_ptr == nullptr);

    /* Create new function for current translation block */
    /* TODO: compute the checksum of the tb to see if we can reuse some code */
    std::ostringstream fName;

    // this is where TranslationBlock gets the size for llvm_fn_name (and
    // knowing PANDA never builds with CONFIG_USER_ONLY)
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

        // Add instrumented helper functions to the JIT
        jitPendingModule();

        m_CPUArchStateType = m_module->getTypeByName(m_CPUArchStateName);
    }
    assert(m_CPUArchStateType);

    llvm::Type *pCPUArchStateType =
        PointerType::getUnqual(m_CPUArchStateType);
    FunctionType *tbFunctionType = FunctionType::get(wordType(),
            std::vector<llvm::Type*>{pCPUArchStateType}, false);
    m_tbFunction = Function::Create(tbFunctionType,
            Function::ExternalLinkage, fName.str(), m_module.get());
    BasicBlock *basicBlock = BasicBlock::Create(*m_context,
            "entry", m_tbFunction);
    m_builder.SetInsertPoint(basicBlock);

    m_tcgContext = s;

    /* Prepare globals and temps information */
    initGlobalsAndLocalTemps();

    MDNode *PCUpdateMD = MDNode::get(*m_context, MDString::get(*m_context, "pcupdate"));
    MDNode *RRUpdateMD = MDNode::get(*m_context, MDString::get(*m_context, "rrupdate"));
    MDNode *RuntimeMD = MDNode::get(*m_context, MDString::get(*m_context, "runtime"));

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
            Constant *PC = constInt(64, args[0]);
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
    if(!isa<ReturnInst>(m_tbFunction->back().back())) {
        m_builder.CreateRet(constWord(0));
    }

    /* Clean up unused m_values */
    for(int i=0; i<TCG_MAX_TEMPS; ++i) {
        delValue(i);
    }

    /* Delete pointers after deleting values */
    for(int i=0; i<TCG_MAX_TEMPS; ++i) {
        delPtrForValue(i);
    }

    for(int i=0; i<TCG_MAX_LABELS; ++i) {
        delLabel(i);
    }

    for (auto &it : m_envOffsetValues) {
        freeValue(it.second);
    }
    m_envOffsetValues.clear();

    // run all specified function passes
    m_functionPassManager->run(*m_tbFunction);

#ifndef NDEBUG
    verifyFunction(*m_tbFunction);
#endif

    if(execute_llvm || qemu_loglevel_mask(CPU_LOG_LLVM_ASM)) {
        jitPendingModule();

        auto symbol = jit->lookup(fName.str());
        assert(symbol);
        tb->llvm_tc_ptr = (uint8_t *) symbol->getAddress();
        assert(tb->llvm_tc_ptr);

        // if desired, have to log the LLVM IR before JIT the Function, as
        // JITting will trash the Function instance
        checkAndLogLLVMIR();

        // it is not possible to determine the number of bytes in the generated
        // host assembly for this LLVM function until the function is JITted,
        // which can be forcibly done by looking up the associated symbol in the
        // proper symbol table and registering a NotifyLoadedFunction callback
        // (as was done above) to get the size of the associated section
        // first, we need to save the LLVM function name to find the desired
        // section
        g_strlcpy(tb->llvm_fn_name, fName.str().c_str(),
            sizeof(tb->llvm_fn_name));

        // then, need to look up the LLVM function symbol in the magic symbol
        // table - this is NOT the main symbol table that is searched by default
        // the only way to get the special symbol table is by name, and there's
        // no programmatic way to get the name.  Fortunately, the symbol table
        // name is hardcoded in LLVM's
        // CompileOnDemandLayer::getPerDylibResources().  A CompileOnDemandLayer
        // is constructed and used by LLLazyJIT.  This implementation detail is
        // relied upon to look up the proper symbol instance, which provides the
        // starting address, and kicks off the NotifyLoadedFunction callback
        // which finds the length of the generated assembly code in bytes and
        // stores it in section_size.
        pending_tb = tb;
        need_section_size = true;
        auto dylib = jit->getJITDylibByName("main.impl");
        if (nullptr == dylib) {
            std::cerr <<
            "Cannot find magic symbol table - has the name changed again?" << 
            std::endl;
            assert(false);
        }
        auto fnsym = jit->lookup(*dylib, tb->llvm_fn_name);
        // assert forces the return value to be checked for an error, so don't
        // fail the next step
        assert(fnsym);
        tb->llvm_asm_ptr = (uint8_t *)fnsym->getAddress();
        if (need_section_size) {
            std::cerr << "Cannot determine section size for " <<
                    tb->llvm_fn_name << std::endl;
            assert(false);
        }
        tb->llvm_tc_end = tb->llvm_asm_ptr + section_size;
    } else {
        checkAndLogLLVMIR();
    }
}

/* rwhelan: to restart LLVM again, there is either a bug with the
 * FunctionPassManager destructor not unregistering passes, or we need to
 * manually unregister our passes somehow.  If you don't add passes into LLVM,
 * then switching between TCG and LLVM should work fine.
 */
TCGLLVMTranslator::~TCGLLVMTranslator()
{
    if (m_functionPassManager) {
        delete m_functionPassManager;
        m_functionPassManager = nullptr;
    }

    /*if (llvm::llvm_is_multithreaded()) {
        LLVMStopMultithreaded();
    }*/
}

inline void TCGLLVMTranslator::delLabel(int idx)
{
    if(m_labels[idx] && m_labels[idx]->use_empty() &&
            !m_labels[idx]->getParent()) {
        delete m_labels[idx];
    }
    m_labels[idx] = nullptr;
}

/*
 * rwhelan: This is needed since the memory access helpers now need a handle to
 * env
 */
inline Value* TCGLLVMTranslator::getEnv() {
    return m_tbFunction->arg_begin();
}

/***********************************/
/* External interface for C++ code */

void TCGLLVMTranslator::writeModule(const char *path)
{
    std::error_code Error;
    raw_fd_ostream outfile(path, Error);
    if (verifyModule(*getModule(), &outs())) {
        exit(1);
    }
    WriteBitcodeToFile(*getModule(), outfile);
}

/*****************************/
/* Functions for QEMU c code */

void tcg_llvm_initialize()
{
    assert(tcg_llvm_translator == nullptr);
    //assert(llvm_start_multithreaded());

    InitializeNativeTarget();
    InitializeNativeTargetAsmPrinter();
    InitializeNativeTargetAsmParser();

    tcg_llvm_translator = new TCGLLVMTranslator;
}

void tcg_llvm_destroy()
{
    assert(tcg_llvm_translator != nullptr);
    delete tcg_llvm_translator;
    tcg_llvm_translator = nullptr;
}

void tcg_llvm_gen_code(TCGLLVMTranslator *l, TCGContext *s, TranslationBlock *tb)
{
    l->generateCode(s, tb);
}

void tcg_llvm_tb_alloc(TranslationBlock *tb)
{
    tb->llvm_fn_name[0] = '\0';
    tb->llvm_asm_ptr = nullptr;
    tb->llvm_tc_ptr = nullptr;
    tb->llvm_tc_end = nullptr;
}

void tcg_llvm_tb_free(TranslationBlock *tb)
{
    if(tb->llvm_tc_ptr) {
        tb->llvm_fn_name[0] = '\0';
        tb->llvm_asm_ptr = nullptr;
        tb->llvm_tc_ptr = nullptr;
        tb->llvm_tc_end = nullptr;
    }
}

const char* tcg_llvm_get_func_name(TranslationBlock *tb)
{
    if (tb->llvm_fn_name[0]) {
        return tb->llvm_fn_name;
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

void tcg_llvm_write_module(TCGLLVMTranslator *l, const char *path)
{
    l->writeModule(path);
}

uintptr_t tcg_llvm_get_module_ptr(TCGLLVMTranslator *l) {
    return (uintptr_t)l->getModule();
}
