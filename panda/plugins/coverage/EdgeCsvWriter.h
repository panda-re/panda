#ifndef COVERAGE2_EDGECSVWRITER_H
#define COVERAGE2_EDGECSVWRITER_H

#include <fstream>
#include <string>

#include "Edge.h"
#include "RecordProcessor.h"

namespace coverage2
{

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
