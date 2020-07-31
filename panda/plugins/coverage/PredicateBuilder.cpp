#include "PredicateBuilder.h"

#include "AlwaysTruePredicate.h"
#include "CompoundPredicate.h"
#include "InKernelPredicate.h"
#include "PcRangePredicate.h"
#include "ProcessNamePredicate.h"

namespace coverage
{

PredicateBuilder::PredicateBuilder() : predicate(new AlwaysTruePredicate)
{
}

PredicateBuilder& PredicateBuilder::with_process_name(const std::string &pn)
{
    std::unique_ptr<Predicate> pnp(new ProcessNamePredicate(pn));
    predicate.reset(new CompoundPredicate(std::move(predicate), std::move(pnp)));
    return *this;
}

PredicateBuilder& PredicateBuilder::with_pc_range(target_ulong low, target_ulong high)
{
    std::unique_ptr<Predicate> pcrp(new PcRangePredicate(low, high));
    predicate.reset(new CompoundPredicate(std::move(predicate), std::move(pcrp)));
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
    return std::move(tmp);
}

}
