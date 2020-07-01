#include "PcRangePredicate.h"

namespace coverage2
{

PcRangePredicate::PcRangePredicate(target_ulong start, target_ulong end)
        : pc_start(start), pc_end(end)
{
}

bool PcRangePredicate::eval(CPUState *cpu, target_ulong pc)
{
    return pc_start <= pc && pc <= pc_end;
}

}
