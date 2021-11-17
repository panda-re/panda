#include "PredicateBuilder.h"

#include "AlwaysTruePredicate.h"
#include "CompoundPredicate.h"
#include "ExcludedPcRangePredicate.h"
#include "InKernelPredicate.h"
#include "PcRangePredicate.h"

namespace coverage
{

PredicateBuilder::PredicateBuilder() : predicate(new AlwaysTruePredicate)
{
}

PredicateBuilder& PredicateBuilder::with_pc_range(target_ulong low, target_ulong high)
{
    std::unique_ptr<Predicate> pcrp(new PcRangePredicate(low, high));
    predicate.reset(new CompoundPredicate(std::move(predicate), std::move(pcrp)));
    return *this;
}

PredicateBuilder& PredicateBuilder::without_pc_range(target_ulong low, target_ulong high)
{
    std::unique_ptr<Predicate> epcrp(new ExcludedPcRangePredicate(low, high));
    predicate.reset(new CompoundPredicate(std::move(predicate), std::move(epcrp)));
    return *this;
}

PredicateBuilder& PredicateBuilder::in_kernel(bool ik)
{
    std::unique_ptr<Predicate> ikp(new InKernelPredicate(ik));
    predicate.reset(new CompoundPredicate(std::move(predicate), std::move(ikp)));
    return *this;
}

std::unique_ptr<Predicate> PredicateBuilder::build()
{
    std::unique_ptr<Predicate> tmp = std::move(predicate);
    predicate.reset(new AlwaysTruePredicate);
    return tmp;
}

}
