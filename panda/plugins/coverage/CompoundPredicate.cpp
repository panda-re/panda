#include "CompoundPredicate.h"

namespace coverage
{

CompoundPredicate::CompoundPredicate(std::unique_ptr<Predicate> p1,
    std::unique_ptr<Predicate> p2) : predicate1(std::move(p1)),
                                     predicate2(std::move(p2))
{
}

bool CompoundPredicate::eval(CPUState *cpu, TranslationBlock *tb)
{
    return predicate1->eval(cpu, tb) && predicate2->eval(cpu, tb);
}

}
