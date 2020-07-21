#ifndef COVERAGE2_INKERNEL_PREDICATE_H
#define COVERAGE2_INKERNEL_PREDICATE_H

#include "Predicate.h"

namespace coverage
{

class InKernelPredicate : public Predicate
{
public:
    InKernelPredicate(bool ik);

    bool eval(CPUState *cpu, TranslationBlock *tb) override;
private:
    bool in_kernel;
};

}

#endif
