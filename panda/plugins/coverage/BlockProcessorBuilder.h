#ifndef COVERAGE_BLOCKPROCESSOR_BUILDER_H
#define COVERAGE_BLOCKPROCESSOR_BUILDER_H

#include <memory>
#include <string>

#include "Block.h"
#include "AsidBlock.h"
#include "OsiBlock.h"
#include "Edge.h"
#include "RecordProcessor.h"

namespace coverage
{

/**
 * A class that wraps building a RecordProcessor<Block> object into an easy to
 * use interface.
 */
class BlockProcessorBuilder
{
public:
    BlockProcessorBuilder();

    /**
     * Sets the output mode for the resulting record processor object.
     */
    BlockProcessorBuilder& with_output_mode(const std::string &m);

    /**
     * Turns on unique filtering for the resulting record processor object.
     */
    BlockProcessorBuilder& with_unique_filter();

    /**
     * Sets the output filename.
     */
    BlockProcessorBuilder& with_filename(const std::string &f);

    /**
     * Constructs the record processor object.
     */
    std::unique_ptr<RecordProcessor<Block>> build();
private:
    std::string mode;
    std::string filename;
    bool unique;
};

}

#endif
