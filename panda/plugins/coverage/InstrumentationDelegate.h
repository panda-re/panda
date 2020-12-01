#ifndef COVERAGE_INSTRUMENTATION_DELEGATE_H
#define COVERAGE_INSTRUMENTATION_DELEGATE_H

#include "panda/plugin.h"

namespace coverage
{

class InstrumentationDelegate
{
public:
    virtual ~InstrumentationDelegate() = 0;
    virtual void instrument(CPUState *cpu, TranslationBlock *tb) = 0;

};

}

#endif
