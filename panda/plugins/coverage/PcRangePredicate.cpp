#include "PcRangePredicate.h"

namespace coverage
{

PcRangePredicate::PcRangePredicate(target_ulong start, target_ulong end)
        : pc_start(start), pc_end(end)
{
}

bool PcRangePredicate::eval(CPUState *cpu, TranslationBlock *tb)
{
    return pc_start <= tb->pc && (tb->pc + tb->size) < pc_end;
}

}
