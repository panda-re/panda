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
__class_compat_decl(TCGLLVMContext)
struct TCGLLVMRuntime;

/* defined in panda/llvm/tcg-llvm.cpp */
extern __class_compat_var TCGLLVMContext *tcg_llvm_ctx;
extern __class_compat_var TCGLLVMRuntime tcg_llvm_runtime;

/* defined in vl.c */
void tcg_llvm_initialize(void);
void tcg_llvm_destroy(void);

/* defined in panda/llvm/tcg-llvm.cpp */
void tcg_llvm_tb_alloc(struct TranslationBlock *tb);
void tcg_llvm_tb_free(struct TranslationBlock *tb);
const char* tcg_llvm_get_func_name(struct TranslationBlock *tb);
void tcg_llvm_gen_code(__class_compat_var TCGLLVMContext *l, struct TCGContext *s, struct TranslationBlock *tb);
uintptr_t tcg_llvm_qemu_tb_exec(CPUArchState *env, struct TranslationBlock *tb);
void tcg_llvm_write_module(__class_compat_var TCGLLVMContext *l, const char *path);

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
/***********************************/
/* External interface for C++ code */

namespace llvm {
class Function;
class LLVMContext;
class Module;
class ModuleProvider;
class ExecutionEngine;
class FunctionPassManager;
}  // namespace llvm

class TCGLLVMContextPrivate;

class TCGLLVMContext {
   private:
    TCGLLVMContextPrivate* m_private;

   public:
    TCGLLVMContext();
    ~TCGLLVMContext();
    llvm::LLVMContext& getLLVMContext();
    llvm::Module* getModule();
    llvm::ModuleProvider* getModuleProvider();
    llvm::ExecutionEngine* getExecutionEngine();
    void deleteExecutionEngine();
    llvm::FunctionPassManager* getFunctionPassManager() const;
    void generateCode(struct TCGContext* s, struct TranslationBlock* tb);
    void writeModule(const char* path);
};

#endif

#undef __class_compat_decl
#undef __class_compat_var

