#include "AlwaysTruePredicate.h"

namespace coverage2
{

bool AlwaysTruePredicate::eval(CPUState *cpu, target_ulong pc)
{
    return true;
}

}
