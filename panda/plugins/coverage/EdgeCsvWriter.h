#ifndef COVERAGE_EDGECSVWRITER_H
#define COVERAGE_EDGECSVWRITER_H

#include <fstream>
#include <string>

#include "Edge.h"
#include "RecordProcessor.h"

namespace coverage
{

/**
 * Writes Edge structs into a CSV file.
 */
class EdgeCsvWriter : public RecordProcessor<Edge>
{
public:
    EdgeCsvWriter(const std::string &filename);
    void handle(Edge record) override;
private:
    std::ofstream os;
};

}

#endif
