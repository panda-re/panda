#include "UniqueAsidPredicate.h"

namespace coverage2
{

bool UniqueAsidPredicate::eval(CPUState *cpu, TranslationBlock *tb)
{
    UniqueAsidRecord rec;
    rec.asid = panda_current_asid(cpu);
    rec.pc = tb->pc;
    auto tmp = seen.insert(rec);
    return std::get<1>(tmp);
}

}
