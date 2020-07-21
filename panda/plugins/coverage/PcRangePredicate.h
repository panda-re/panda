#ifndef COVERAGE_PCRANGE_PREDICATE_H
#define COVERAGE_PCRANGE_PREDICATE_H

#include "Predicate.h"

namespace coverage
{

/**
 * A predicate that determines if the PC falls in a given range.
 */
class PcRangePredicate : public Predicate
{
public:
    PcRangePredicate(target_ulong start, target_ulong end);

    bool eval(CPUState *cpu, TranslationBlock *tb) override;
private:
    target_ulong pc_start;
    target_ulong pc_end;
};

}

#endif
