#ifndef COVERAGE2_OSIBLOCK_CSVWRITER_H
#define COVERAGE2_OSIBLOCK_CSVWRITER_H

#include <fstream>
#include <string>

#include "OsiBlock.h"
#include "RecordProcessor.h"

namespace coverage2
{

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
