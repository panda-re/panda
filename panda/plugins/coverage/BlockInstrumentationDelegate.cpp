#include "panda/tcg-utils.h"

#include "BlockInstrumentationDelegate.h"

namespace coverage
{

static void block_callback(RecordProcessor<Block> *bp, TranslationBlock *tb)
{
    Block block {
        .addr = tb->pc,
        .size = tb->size
    };
    bp->handle(block);
}

BlockInstrumentationDelegate::BlockInstrumentationDelegate(std::unique_ptr<RecordProcessor<Block>> bp)
    : block_processor(std::move(bp))
{
}

void BlockInstrumentationDelegate::instrument(CPUState *cpu, TranslationBlock *tb)
{
    TCGOp *insert_point = find_first_guest_insn();
    assert(NULL != insert_point);
    insert_call(&insert_point, &block_callback, block_processor.get(), tb);
}

}
