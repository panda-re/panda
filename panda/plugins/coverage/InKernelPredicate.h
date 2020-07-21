#ifndef COVERAGE_INKERNEL_PREDICATE_H
#define COVERAGE_INKERNEL_PREDICATE_H

#include "Predicate.h"

namespace coverage
{

/**
 * A predicate for filtering on whether or not the guest is in kernel mode or
 * not.
 */
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
