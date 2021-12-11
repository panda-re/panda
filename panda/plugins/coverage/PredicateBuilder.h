#ifndef COVERAGE_PREDICATE_BUILDER_H
#define COVERAGE_PREDICATE_BUILDER_H

#include <memory>

#include "Predicate.h"

namespace coverage
{

/**
 * A class that wraps the construction of predicates into an easy to use
 * interface.
 */
class PredicateBuilder
{
public:
    PredicateBuilder();
    PredicateBuilder& with_pc_range(target_ulong low, target_ulong high);
    PredicateBuilder& without_pc_range(target_ulong low, target_ulong high);
    PredicateBuilder& in_kernel(bool ik);
    std::unique_ptr<Predicate> build(); 
private:
    std::unique_ptr<Predicate> predicate;
};

}

#endif
