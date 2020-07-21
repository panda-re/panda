#ifndef COVERAGE_OSIBLOCK_CSVWRITER_H
#define COVERAGE_OSIBLOCK_CSVWRITER_H

#include <fstream>
#include <string>

#include "OsiBlock.h"
#include "RecordProcessor.h"

namespace coverage
{

/**
 * Writes OsiBlock structs to a CSV file.
 */
class OsiBlockCsvWriter : public RecordProcessor<OsiBlock>
{
public:
    OsiBlockCsvWriter(const std::string &filename);
    void handle(OsiBlock record) override;
private:
    std::ofstream os;
};

}

#endif
