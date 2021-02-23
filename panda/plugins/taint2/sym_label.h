#ifndef __SYM_LABEL_H_
#define __SYM_LABEL_H_

#include "label_set.h"

#include <cstdint>

#ifdef SHAD_LLVM
#include <z3++.h>
#endif
struct SymLabel {
    
#ifdef SHAD_LLVM
    z3::expr *expr = NULL;
    z3::expr *full_expr = NULL;
#else
    void *expr = NULL;
    void *full_expr = NULL;
#endif
    uint8_t full_size = 0;
    uint8_t offset = 0;
    SymLabel():
        expr(nullptr), full_expr(nullptr), full_size(0), offset(0) {}
};

extern "C" {
typedef SymLabel *SymLabelP;
}



#endif
