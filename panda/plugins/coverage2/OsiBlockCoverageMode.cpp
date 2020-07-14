#include <memory>

#include "panda/plugin.h"
#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include "OsiBlockCoverageMode.h"
#include "utils.h"

namespace coverage2
{

static void callback(std::ostream *os, CPUState *cpu, TranslationBlock *tb)
{
    std::unique_ptr<OsiProc, void(*)(OsiProc*)> process(get_current_process(cpu), free_osiproc);
    std::unique_ptr<OsiThread, void(*)(OsiThread*)> thread(get_current_thread(cpu), free_osithread);

    *os << process->name << ",";
    *os << std::dec << thread->pid << ",";
    *os << std::dec << thread->tid << ",";
    *os << std::dec << panda_in_kernel(cpu) << ",";
    *os << "0x" << std::hex << tb->pc << ",";
    *os << std::dec << tb->size;
    *os << "\n";
}

OsiBlockCoverageMode::OsiBlockCoverageMode(const std::string &filename)
        : output_stream(filename)
{
    panda_require("osi");
    assert(init_osi_api());

    output_stream << "process\n";
    output_stream << "process name,process id,thread id,in kernel,block address,block size\n";
}

void OsiBlockCoverageMode::process_block(CPUState *cpu, TranslationBlock *tb)
{
    TCGOp *insert_point = find_first_guest_insn();    
    insert_call(&insert_point, &callback, &output_stream, cpu, tb);
}

void OsiBlockCoverageMode::process_results()
{
}

}
