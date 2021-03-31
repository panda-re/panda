#ifndef COVERAGE_BLOCKINSTRUMENTATIONDELEGATE_H
#define COVERAGE_BLOCKINSTRUMENTATIONDELEGATE_H

#include <memory>

#include "Block.h"
#include "RecordProcessor.h"
#include "InstrumentationDelegate.h"

namespace coverage
{

class BlockInstrumentationDelegate : public InstrumentationDelegate
{
public:
    BlockInstrumentationDelegate(std::shared_ptr<RecordProcessor<Block>> bp);

    void instrument(CPUState *cpu, TranslationBlock *tb) override;

private:
    std::shared_ptr<RecordProcessor<Block>> block_processor;
};

}

#endif
