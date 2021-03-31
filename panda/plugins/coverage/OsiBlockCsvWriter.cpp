#include "OsiBlockCsvWriter.h"
#include "metadata_writer.h"

namespace coverage
{

OsiBlockCsvWriter::OsiBlockCsvWriter(const std::string &filename,
    bool start_disabled)
{
    os.exceptions(std::ofstream::failbit | std::ofstream::badbit);
    if (!start_disabled) {
        os.open(filename);
        write_header();
    }
}

void OsiBlockCsvWriter::handle(OsiBlock record)
{
    if (!os.is_open()) {
        return;
    }

    os << record.process_name << ","
       << std::dec << record.pid << ","
       << std::dec << record.tid << ","
       << std::dec << record.in_kernel << ","
       << "0x" << std::hex << record.block.addr << ","
       << std::dec << record.block.size << "\n";
}

void OsiBlockCsvWriter::write_header()
{
    write_metadata(os);
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
