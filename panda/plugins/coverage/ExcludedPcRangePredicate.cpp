#include "ExcludedPcRangePredicate.h"

namespace coverage
{

ExcludedPcRangePredicate::ExcludedPcRangePredicate(target_ulong start, target_ulong end)
        : pc_start(start), pc_end(end)
{
}

bool ExcludedPcRangePredicate::eval(CPUState *cpu, TranslationBlock *tb)
{
	// the (pc+size) is the address of the first byte OUTSIDE this block
	return ((tb->pc + tb->size) <= pc_start) || (tb->pc > pc_end);
}

}
