#ifndef COVERAGE2_ASIDBLOCK_GENERATOR_H
#define COVERAGE2_ASIDBLOCK_GENERATOR_H

#include <memory>

#include "AsidBlock.h"
#include "RecordProcessor.h"

namespace coverage
{

class AsidBlockGenerator : public RecordProcessor<Block>
{
public:
    AsidBlockGenerator(CPUState *c,
                       std::unique_ptr<RecordProcessor<AsidBlock>> d);
    void handle(Block record) override;
private:
    CPUState *cpu;
    std::unique_ptr<RecordProcessor<AsidBlock>> delegate;
};

}

#endif
