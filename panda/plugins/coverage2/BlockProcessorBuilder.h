#ifndef COVERAGE2_BLOCKPROCESSOR_BUILDER_H
#define COVERAGE2_BLOCKPROCESSOR_BUILDER_H

#include <memory>
#include <string>

#include "Block.h"
#include "AsidBlock.h"
#include "OsiBlock.h"
#include "Edge.h"
#include "RecordProcessor.h"

namespace coverage2
{

class BlockProcessorBuilder
{
public:
    BlockProcessorBuilder();

    void with_output_mode(const std::string &m);
    void with_unique_filter();
    void with_filename(const std::string &f);
    std::unique_ptr<RecordProcessor<Block>> build();
private:
    std::string mode;
    std::string filename;
    bool unique;
};

}

#endif
