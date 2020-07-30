#include "EdgeGenerator.h"

namespace coverage
{

static Block dummy {
    .addr = static_cast<target_ulong>(-1),
    .size = static_cast<target_ulong>(-1)
};

EdgeGenerator::EdgeGenerator(std::unique_ptr<RecordProcessor<Edge>> d)
    : delegate(std::move(d)), previous_block(dummy)
{
}

void EdgeGenerator::handle(Block record)
{
    Edge edge {
        .from = previous_block,
        .to = record
    };
    previous_block = record;

    if (unlikely(dummy == edge.from)) {
        return;
    }
    delegate->handle(edge);
}

}
