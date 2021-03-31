#ifndef COVERAGE_EDGECSVWRITER_H
#define COVERAGE_EDGECSVWRITER_H

#include <fstream>
#include <string>

#include "Edge.h"
#include "RecordProcessor.h"

#include "CoverageMonitorDelegate.h"

namespace coverage
{

/**
 * Writes Edge structs into a CSV file.
 */
class EdgeCsvWriter : public RecordProcessor<Edge>,
                      public CoverageMonitorDelegate
{
public:
    EdgeCsvWriter(const std::string &filename, bool start_disabled);
    void handle(Edge record) override;

    void handle_enable(const std::string& filename);
    void handle_disable();
private:
    void write_header();

    std::ofstream os;
};

}

#endif
