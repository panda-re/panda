#include <iostream>

#include "AsidBlockCsvWriter.h"
#include "metadata_writer.h"

namespace coverage
{

AsidBlockCsvWriter::AsidBlockCsvWriter(const std::string &filename,
    bool start_disabled)
{
    os.exceptions(std::ofstream::failbit | std::ofstream::badbit);
    if (!start_disabled) {
        os.open(filename);
        write_header();
    }
}

void AsidBlockCsvWriter::handle(AsidBlock record)
{
    if (!os.is_open()) {
        return;
    }

    os << "0x" << std::hex << record.asid << ","
       << std::dec << record.in_kernel << ","
       << "0x" << std::hex << record.block.addr << ","
       << std::dec << record.block.size << "\n";
}

void AsidBlockCsvWriter::write_header()
{
    write_metadata(os);
    os << "asid\n";
    os << "asid,in kernel,block address,block size\n";
}

void AsidBlockCsvWriter::handle_enable(const std::string& filename)
{
    os.open(filename);
    write_header();
}

void AsidBlockCsvWriter::handle_disable()
{
    os.close();
}

}
