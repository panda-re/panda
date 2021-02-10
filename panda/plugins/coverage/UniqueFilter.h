#ifndef COVERAGE_UNIQUEFILTER_H
#define COVERAGE_UNIQUEFILTER_H

#include <memory>
#include <unordered_set>

#include "CoverageMonitorDelegate.h"
#include "RecordProcessor.h"

namespace coverage
{

/**
 * A generic record processor that filters out unique records before passing
 * them to a delegate RecordProcessor of the same record type.
 */
template<typename RecordType>
class UniqueFilter : public RecordProcessor<RecordType>,
                     public CoverageMonitorDelegate
{
public:
    /**
     * Constructs a new UniqueFilter and takes ownership of the delegate.
     */
    UniqueFilter(std::shared_ptr<RecordProcessor<RecordType>> d)
        : delegate(d)
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

    void handle_enable(const std::string& filename) override
    {
        seen.clear();
    }

    void handle_disable() override
    {
    }

private:
    std::shared_ptr<RecordProcessor<RecordType>> delegate;
    std::unordered_set<RecordType> seen;
};

}

#endif
