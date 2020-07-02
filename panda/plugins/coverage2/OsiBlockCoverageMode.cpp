#include <memory>

#include "OsiBlockCoverageMode.h"

#include "osi/osi_types.h"
#include "osi/osi_ext.h"

namespace coverage2
{

OsiBlockCoverageMode::OsiBlockCoverageMode(const std::string &filename)
        : output_stream(filename)
{
    output_stream << "process\n";
    output_stream << "process name,process id,thread id,in kernel,block address,block size\n";
}

void OsiBlockCoverageMode::process_block(CPUState *cpu, TranslationBlock *tb)
{
    std::unique_ptr<OsiProc, void(*)(OsiProc*)> process(get_current_process(cpu), free_osiproc);
    std::unique_ptr<OsiThread, void(*)(OsiThread*)> thread(get_current_thread(cpu), free_osithread);

    output_stream << process->name << ",";
    output_stream << std::dec << thread->pid << ",";
    output_stream << std::dec << thread->tid << ",";
    output_stream << std::dec << panda_in_kernel(cpu) << ",";
    output_stream << "0x" << std::hex << tb->pc << ",";
    output_stream << std::dec << tb->size;
    output_stream << "\n";
}

}
