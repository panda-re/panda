#include "EdgeCsvWriter.h"

namespace coverage
{

EdgeCsvWriter::EdgeCsvWriter(const std::string &filename) : os(filename)
{
    os << "from pc,from size,to pc,to size\n";
}

void EdgeCsvWriter::handle(Edge record)
{
    os << "0x" << std::hex << record.from.addr << ","
       << std::dec << record.from.size << ","
       << "0x" << std::hex << record.to.addr << ","
       << std::dec << record.to.size << "\n";
}

}
