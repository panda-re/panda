#ifndef COVERAGE_ASIDBLOCK_GENERATOR_H
#define COVERAGE_ASIDBLOCK_GENERATOR_H

#include <memory>

#include "AsidBlock.h"
#include "RecordProcessor.h"

namespace coverage
{

/**
 * A RecordProcessor that constructs an AsidBlock before passing it to a
 * delegate RecordProcessor.
 */
class AsidBlockGenerator : public RecordProcessor<Block>
{
public:
    AsidBlockGenerator(CPUState *c,
                       std::shared_ptr<RecordProcessor<AsidBlock>> d);
    void handle(Block record) override;
private:
    CPUState *cpu;
    std::shared_ptr<RecordProcessor<AsidBlock>> delegate;
};

}

#endif
