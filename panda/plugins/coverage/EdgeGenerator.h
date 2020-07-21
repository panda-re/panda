#ifndef COVERAGE_EDGEGENERATOR_H
#define COVERAGE_EDGEGENERATOR_H

#include <memory>

#include "Block.h"
#include "Edge.h"
#include "RecordProcessor.h"

namespace coverage
{

/**
 * Converts blocks into edges by emitting an Edge every other call to handle.
 */
class EdgeGenerator : public RecordProcessor<Block>
{
public:
    EdgeGenerator(std::unique_ptr<RecordProcessor<Edge>> d);
    void handle(Block record) override;
private:
    std::unique_ptr<RecordProcessor<Edge>> delegate;
    Block previous_block;
};

}

#endif
