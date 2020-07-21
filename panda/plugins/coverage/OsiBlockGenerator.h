#ifndef COVERAGE_OSIBLOCK_GENERATOR_H
#define COVERAGE_OSIBLOCK_GENERATOR_H

#include <memory>

#include "OsiBlock.h"
#include "RecordProcessor.h"

namespace coverage
{

/**
 * Transforms a regular Block struct into an OsiBlock.
 */
class OsiBlockGenerator : public RecordProcessor<Block>
{
public:
    OsiBlockGenerator(CPUState *c,
                       std::unique_ptr<RecordProcessor<OsiBlock>> d);
    void handle(Block record) override;
private:
    CPUState *cpu;
    std::unique_ptr<RecordProcessor<OsiBlock>> delegate;
};

}

#endif
