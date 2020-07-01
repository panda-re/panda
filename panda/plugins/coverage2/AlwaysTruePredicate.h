#ifndef COVERAGE2_ALWAYSTRUE_PREDICATE_H
#define COVERAGE2_ALWAYSTRUE_PREDICATE_H

#include "Predicate.h"

namespace coverage2
{

/**
 * A predicate that is always true.
 */
class AlwaysTruePredicate : public Predicate
{
public:
    bool eval(CPUState *cpu, target_ulong pc) override;
};

}

#endif
