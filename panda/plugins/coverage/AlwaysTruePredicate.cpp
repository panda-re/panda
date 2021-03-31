#include "AlwaysTruePredicate.h"

namespace coverage
{

bool AlwaysTruePredicate::eval(CPUState *cpu, TranslationBlock *tb)
{
    return true;
}

}
