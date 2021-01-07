#ifndef COVERAGE_ASIDBLOCK_CSVWRITER_H
#define COVERAGE_ASIDBLOCK_CSVWRITER_H

#include <fstream>
#include <string>

#include "AsidBlock.h"
#include "RecordProcessor.h"
#include "CoverageMonitorDelegate.h"

namespace coverage
{

/**
 * A RecordProcessor that writes AsidBlock structs to a CSV file.
 */
class AsidBlockCsvWriter : public RecordProcessor<AsidBlock>,
                           public CoverageMonitorDelegate
{
public:
    AsidBlockCsvWriter(const std::string &filename, bool start_disabled);
    void handle(AsidBlock record) override;

    void handle_enable(const std::string& filename) override;
    void handle_disable() override;

private:
    void write_header();
    std::ofstream os;
};

}

#endif
