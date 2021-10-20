#include "OsiBlockCsvWriter.h"
#include "metadata_writer.h"

namespace coverage
{

OsiBlockCsvWriter::OsiBlockCsvWriter(const std::string &filename,
    bool _summarize_results, bool start_disabled)
{
    os.exceptions(std::ofstream::failbit | std::ofstream::badbit);
    if (!start_disabled) {
        os.open(filename);
        write_header();
    }

    summarize_results = _summarize_results;
}

void OsiBlockCsvWriter::handle(OsiBlock record)
{
    if (summarize_results) {
        // If this is a new key, initialize it with an empty set
        cov_map.emplace(record.process_name, std::unordered_set<target_ulong>());
        // Set must exist now, add this block
        cov_map[record.process_name].insert(record.block.addr);
    } else {
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
}

void OsiBlockCsvWriter::write_header()
{
    write_metadata(os);
    os << "process\n";
    if (summarize_results){
        os << "process name,block count\n";
    } else {
        os << "process name,process id,thread id,in kernel,block address,block size\n";
    }
}

void OsiBlockCsvWriter::handle_enable(const std::string& filename)
{
    os.open(filename);
    write_header();
}

void OsiBlockCsvWriter::handle_disable()
{
    if (!os.is_open()) {
        return;
    }

    if (summarize_results) {
        // dump results
        for ( auto it = cov_map.begin(); it != cov_map.end(); ++it )  {
            std::string name = it->first;
            size_t sz = it->second.size();
            os << name << "," << sz << "\n";
        }
    }
    os.close();
}

}
