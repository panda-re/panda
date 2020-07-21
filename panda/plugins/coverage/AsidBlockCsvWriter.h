#ifndef COVERAGE2_ASIDBLOCK_CSVWRITER_H
#define COVERAGE2_ASIDBLOCK_CSVWRITER_H

#include <fstream>
#include <string>

#include "AsidBlock.h"
#include "RecordProcessor.h"

namespace coverage
{

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
