#ifndef COVERAGE_ALWAYSTRUE_PREDICATE_H
#define COVERAGE_ALWAYSTRUE_PREDICATE_H

#include "Predicate.h"

namespace coverage
{

/**
 * A predicate that is always true.
 */
class AlwaysTruePredicate : public Predicate
{
public:
    bool eval(CPUState *cpu, TranslationBlock *tb) override;
};

}

#endif
