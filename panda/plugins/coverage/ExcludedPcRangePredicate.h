#ifndef COVERAGE_EXCLUDEDPCRANGE_PREDICATE_H
#define COVERAGE_EXCLUDEDPCRANGE_PREDICATE_H

#include "Predicate.h"

namespace coverage
{

/**
 * A predicate that determines if a block falls entirely outside a given PC
 * range.
 */
class ExcludedPcRangePredicate : public Predicate
{
public:
    ExcludedPcRangePredicate(target_ulong start, target_ulong end);

    bool eval(CPUState *cpu, TranslationBlock *tb) override;
private:
    target_ulong pc_start;
    target_ulong pc_end;
};

}

#endif
