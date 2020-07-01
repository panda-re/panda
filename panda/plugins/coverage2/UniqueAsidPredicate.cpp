#include "UniqueAsidPredicate.h"

namespace coverage2
{

bool UniqueAsidPredicate::eval(CPUState *cpu, target_ulong pc)
{
    UniqueAsidRecord rec;
    rec.asid = panda_current_asid(cpu);
    rec.pc = pc;
    auto tmp = seen.insert(rec);
    return std::get<1>(tmp);
}

}
