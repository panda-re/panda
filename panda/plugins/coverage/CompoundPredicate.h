#ifndef COVERAGE_COMPOUND_PREDICATE_H
#define COVERAGE_COMPOUND_PREDICATE_H

#include <memory>

#include "Predicate.h"

namespace coverage
{

/**
 * A predicate that combines two predicates.
 */
class CompoundPredicate : public Predicate
{
public:
    CompoundPredicate(std::unique_ptr<Predicate> p1,
                      std::unique_ptr<Predicate> p2);

    /**
     * Returns true if the two predicates are also evaluated as true.
     */
    bool eval(CPUState *cpu, TranslationBlock *tb) override;
private:
    std::unique_ptr<Predicate> predicate1;
    std::unique_ptr<Predicate> predicate2;
};

}

#endif
