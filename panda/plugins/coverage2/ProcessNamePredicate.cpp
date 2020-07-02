#include <memory>

#include "ProcessNamePredicate.h"

#include "osi/osi_types.h"
#include "osi/osi_ext.h"

namespace coverage2
{

ProcessNamePredicate::ProcessNamePredicate(const std::string& pname)
        : process_name(pname)
{
}

bool ProcessNamePredicate::eval(CPUState *cpu, TranslationBlock *tb)
{
    std::unique_ptr<OsiProc, void(*)(OsiProc *)> proc(get_current_process(cpu), free_osiproc);
    return nullptr != proc && process_name == proc->name;
}

}
