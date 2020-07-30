#include "AsidBlockCsvWriter.h"

namespace coverage
{

AsidBlockCsvWriter::AsidBlockCsvWriter(const std::string &filename) : os(filename)
{
    os << "asid\n";
    os << "asid,in kernel,block address,block size\n";
}

void AsidBlockCsvWriter::handle(AsidBlock record)
{
    os << "0x" << std::hex << record.asid << ","
       << std::dec << record.in_kernel << ","
       << "0x" << std::hex << record.block.addr << ","
       << std::dec << record.block.size << "\n";
}

}
