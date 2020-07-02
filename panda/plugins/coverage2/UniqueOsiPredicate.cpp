#include <memory>

#include "UniqueOsiPredicate.h"

#include "osi/osi_types.h"
#include "osi/osi_ext.h"

namespace coverage2
{

bool UniqueOsiPredicate::eval(CPUState *cpu, TranslationBlock *tb)
{
    std::unique_ptr<OsiThread, void(*)(OsiThread*)> thread(get_current_thread(cpu), free_osithread);
    UniqueOsiRecord rec;
    rec.pid = thread->pid;
    rec.tid = thread->tid;
    rec.pc = tb->pc;
    auto tmp = seen.insert(rec);
    return std::get<1>(tmp);
}

}
