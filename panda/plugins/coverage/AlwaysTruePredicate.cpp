#include "AlwaysTruePredicate.h"

namespace coverage2
{

bool AlwaysTruePredicate::eval(CPUState *cpu, TranslationBlock *tb)
{
    return true;
}

}
