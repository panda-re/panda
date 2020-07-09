#ifndef COVERAGE2_COVERAGEMODE_H
#define COVERAGE2_COVERAGEMODE_H

#include "panda/plugin.h"

namespace coverage2
{

class CoverageMode
{
public:
    virtual ~CoverageMode() = 0;

    virtual void process_block(CPUState *cpu, TranslationBlock *tb) = 0;

    virtual void process_results() = 0;
};

}

#endif
