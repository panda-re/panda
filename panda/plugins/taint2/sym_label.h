#ifndef __SYM_LABEL_H_
#define __SYM_LABEL_H_

#include "label_set.h"

#include <cstdint>
#include <memory>

#ifdef SHAD_LLVM
#include <z3++.h>
#endif
// The symbolic label of a byte
struct SymLabel {
    
#ifdef SHAD_LLVM
    // The expr that contains the byte.
    // Can be used with the offset to obtain the byte expr
    std::shared_ptr<z3::expr> expr;
    // First byte of a larger expr has this set,
    // It can speed up expr look up by avoid concating bytes     
    std::shared_ptr<z3::expr> full_expr;
#else
    // buffers: each shared_ptr takes the space of two pointers
    void *expr = NULL;
    void *expr_1 = NULL;
    void *full_expr = NULL;
    void *full_expr_1 = NULL;
#endif
    // The size of full_expr
    uint8_t full_size = 0;
    // The offset of the byte in expr 
    uint8_t offset = 0;
    SymLabel():
        expr(nullptr), full_expr(nullptr), full_size(0), offset(0) {}
};

extern "C" {
typedef SymLabel *SymLabelP;
}



#endif
