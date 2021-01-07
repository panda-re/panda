#include <iostream>

#include "EdgeCsvWriter.h"
#include "metadata_writer.h"

namespace coverage
{

EdgeCsvWriter::EdgeCsvWriter(const std::string &filename, bool start_disabled)
{
    os.exceptions(std::ofstream::badbit | std::ofstream::failbit);
    if (!start_disabled) {
        os.open(filename);
        write_header();
    }
}

void EdgeCsvWriter::handle(Edge record)
{
    if (!os.is_open()) {
        return;
    }

    os << "0x" << std::hex << record.from.addr << ","
       << std::dec << record.from.size << ","
       << "0x" << std::hex << record.to.addr << ","
       << std::dec << record.to.size << "\n";
}

void EdgeCsvWriter::handle_enable(const std::string& filename)
{
    os.open(filename);
    write_header();
}

void EdgeCsvWriter::handle_disable()
{
    os.close();
}

void EdgeCsvWriter::write_header()
{
    write_metadata(os);
    os << "from pc,from size,to pc,to size\n";
}

}
