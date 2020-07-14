#include "AsidBlockCoverageMode.h"
#include "utils.h"

namespace coverage2
{

static void callback(std::ostream *os, CPUState *cpu, TranslationBlock *tb)
{
    *os << "0x" << std::hex << panda_current_asid(cpu) << ",";
    *os << std::dec << panda_in_kernel(cpu) << ",";
    *os << "0x" << std::hex << tb->pc << ",";
    *os << std::dec << tb->size << "\n";
}

AsidBlockCoverageMode::AsidBlockCoverageMode(const std::string &filename)
        : output_stream(filename)
{
    output_stream << "asid\n";
    output_stream << "asid,in kernel,block address,block size\n";
}

void AsidBlockCoverageMode::process_block(CPUState *cpu, TranslationBlock *tb)
{
    TCGOp *insert_point = find_first_guest_insn();
    insert_call(&insert_point, &callback, &output_stream, cpu, tb);
}

void AsidBlockCoverageMode::process_results()
{
}

}
