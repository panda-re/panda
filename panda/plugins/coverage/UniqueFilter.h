#ifndef COVERAGE_UNIQUEFILTER_H
#define COVERAGE_UNIQUEFILTER_H

#include <memory>
#include <unordered_set>

#include "RecordProcessor.h"

namespace coverage
{

/**
 * A generic record processor that filters out unique records before passing
 * them to a delegate RecordProcessor of the same record type.
 */
template<typename RecordType>
class UniqueFilter : public RecordProcessor<RecordType>
{
public:
    /**
     * Constructs a new UniqueFilter and takes ownership of the delegate.
     */
    UniqueFilter(std::unique_ptr<RecordProcessor<RecordType>> d)
        : delegate(std::move(d))
    {
    }

    /**
     * Try inserting the record into a set. If the item isn't in the set, call
     * the delegate's handle method.
     */
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
