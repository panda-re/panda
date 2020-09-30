#ifndef COVERAGE_PASS_H
#define COVERAGE_PASS_H

#include "panda/plugin.h"

namespace coverage
{

/**
 * An interface for writing a Pass over the TCG block.
 */
class Pass
{
public:
    virtual ~Pass() = 0;
    virtual void before_tcg_codegen(CPUState *cpu, TranslationBlock *tb) = 0;
};

}

#endif
