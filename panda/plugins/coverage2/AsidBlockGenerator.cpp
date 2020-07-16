#include "AsidBlockGenerator.h"

namespace coverage2
{

AsidBlockGenerator::AsidBlockGenerator(
    CPUState *c,
    std::unique_ptr<RecordProcessor<AsidBlock>> d)
        : cpu(c), delegate(std::move(d))
{
}

void AsidBlockGenerator::handle(Block record)
{
    AsidBlock ab {
        .asid = panda_current_asid(first_cpu),
        .in_kernel = panda_in_kernel(first_cpu),
        .block = record
    };
    delegate->handle(ab);
}

}
