#include "panda/plugin.h"
#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include "OsiBlockGenerator.h"

namespace coverage
{

OsiBlockGenerator::OsiBlockGenerator(
    CPUState *c,
    std::unique_ptr<RecordProcessor<OsiBlock>> d)
        : cpu(c), delegate(std::move(d))
{
    panda_require("osi");
    assert(init_osi_api());
}

void OsiBlockGenerator::handle(Block record)
{
    std::unique_ptr<OsiProc, void(*)(OsiProc*)> process(get_current_process(first_cpu), free_osiproc);
    std::unique_ptr<OsiThread, void(*)(OsiThread*)> thread(get_current_thread(first_cpu), free_osithread);

    std::string process_name = "(unknown)";
    bool in_kernel = panda_in_kernel(first_cpu);
    if (!in_kernel && nullptr != process) {
        process_name = process->name;
    } else {
        process_name = "(kernel)";
    }

    OsiBlock ob {
        .pid = thread->pid,
        .tid = thread->tid,
        .in_kernel = in_kernel,
        .process_name = process_name,
        .block = record
    };
    delegate->handle(ob);
}

}
