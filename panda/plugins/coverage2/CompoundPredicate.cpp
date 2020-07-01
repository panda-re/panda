#include "CompoundPredicate.h"

namespace coverage2
{

CompoundPredicate::CompoundPredicate(std::unique_ptr<Predicate> p1,
    std::unique_ptr<Predicate> p2) : predicate1(std::move(p1)),
                                     predicate2(std::move(p2))
{
}

bool CompoundPredicate::eval(CPUState *cpu, target_ulong pc)
{
    return predicate1->eval(cpu, pc) && predicate2->eval(cpu, pc);
}

}
