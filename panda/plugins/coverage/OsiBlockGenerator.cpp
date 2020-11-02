#include "panda/plugin.h"
#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include "OsiBlockGenerator.h"

namespace coverage
{

OsiBlockGenerator::OsiBlockGenerator(std::unique_ptr<RecordProcessor<OsiBlock>> d)
        : delegate(std::move(d))
{
}

void OsiBlockGenerator::handle(Block record)
{
    std::string process_name = "(unknown)";
    bool in_kernel = panda_in_kernel(first_cpu);
    if (!in_kernel) {
        process_name = pname;
    } else {
        process_name = "(kernel)";
    }

    OsiBlock ob {
        .pid = pid,
        .tid = tid,
        .in_kernel = in_kernel,
        .process_name = process_name,
        .block = record
    };
    delegate->handle(ob);
}

void OsiBlockGenerator::task_changed(const std::string& process_name,
                                     target_pid_t pid, target_pid_t tid)
{
    pname = process_name;
    this->pid = pid;
    this->tid = tid;
}

}
