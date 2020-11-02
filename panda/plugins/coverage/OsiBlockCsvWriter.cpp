#include "OsiBlockCsvWriter.h"

namespace coverage
{

OsiBlockCsvWriter::OsiBlockCsvWriter(const std::string &filename) : os(filename)
{
    write_header();
}

void OsiBlockCsvWriter::handle(OsiBlock record)
{
    os << record.process_name << ","
       << std::dec << record.pid << ","
       << std::dec << record.tid << ","
       << std::dec << record.in_kernel << ","
       << "0x" << std::hex << record.block.addr << ","
       << std::dec << record.block.size << "\n";
}

void OsiBlockCsvWriter::write_header()
{
    os << "process\n";
    os << "process name,process id,thread id,in kernel,block address,block size\n";
}

void OsiBlockCsvWriter::handle_enable(const std::string& filename)
{
    os.open(filename);
    write_header();
}

void OsiBlockCsvWriter::handle_disable()
{
    os.close();
}

}
