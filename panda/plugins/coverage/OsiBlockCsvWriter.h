#ifndef COVERAGE_OSIBLOCK_CSVWRITER_H
#define COVERAGE_OSIBLOCK_CSVWRITER_H

#include <fstream>
#include <string>

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
    OsiBlockCsvWriter(const std::string &filename, bool start_disabled);
    void handle(OsiBlock record) override;

    void handle_enable(const std::string& filename) override;
    void handle_disable() override;
private:
    void write_header();
    std::ofstream os;
};

}

#endif
