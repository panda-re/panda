#ifndef COVERAGE_OSIBLOCK_CSVWRITER_H
#define COVERAGE_OSIBLOCK_CSVWRITER_H

#include <fstream>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "CoverageMonitorDelegate.h"
#include "OsiBlock.h"
#include "RecordProcessor.h"

namespace coverage
{



/**
 * Writes OsiBlock structs to a CSV file.
 */
class OsiBlockCsvWriter : public RecordProcessor<OsiBlock>,
                          public CoverageMonitorDelegate
{
public:
    OsiBlockCsvWriter(const std::string &filename, bool summarize_results, bool start_disabled);
    void handle(OsiBlock record) override;

    void handle_enable(const std::string& filename) override;
    void handle_disable() override;
private:
    void write_header();
    bool summarize_results;
    std::ofstream os;
    std::unordered_map<std::string, std::unordered_set<target_ulong>> cov_map;
};

}

#endif
