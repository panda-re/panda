#include "InKernelPredicate.h"

namespace coverage2
{

InKernelPredicate::InKernelPredicate(bool ik) : in_kernel(ik)
{
}

bool InKernelPredicate::eval(CPUState *cpu, TranslationBlock *tb)
{
    return in_kernel == panda_in_kernel(cpu);
}

}
