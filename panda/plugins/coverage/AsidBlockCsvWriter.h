#ifndef COVERAGE_ASIDBLOCK_CSVWRITER_H
#define COVERAGE_ASIDBLOCK_CSVWRITER_H

#include <fstream>
#include <string>

#include "AsidBlock.h"
#include "RecordProcessor.h"

namespace coverage
{

/**
 * A RecordProcessor that writes AsidBlock structs to a CSV file.
 */
class AsidBlockCsvWriter : public RecordProcessor<AsidBlock>
{
public:
    AsidBlockCsvWriter(const std::string &filename);
    void handle(AsidBlock record) override;
private:
    std::ofstream os;
};

}

#endif
