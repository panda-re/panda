#ifndef COVERAGE2_UNIQUEFILTER_H
#define COVERAGE2_UNIQUEFILTER_H

#include <memory>
#include <unordered_set>

#include "RecordProcessor.h"

namespace coverage2
{

template<typename RecordType>
class UniqueFilter : public RecordProcessor<RecordType>
{
public:
    UniqueFilter(std::unique_ptr<RecordProcessor<RecordType>> d) : delegate(std::move(d))
    {
    }

    void handle(RecordType record) override
    {
        if (seen.insert(record).second) {
            delegate->handle(record);
        }
    }

private:
    std::unique_ptr<RecordProcessor<RecordType>> delegate;
    std::unordered_set<RecordType> seen;
};

}

#endif
