#ifndef COVERAGE_RECORDPROCESSOR_H
#define COVERAGE_RECORDPROCESSOR_H

namespace coverage
{

/**
 * An interface for RecordProcessors.
 */
template<typename RecordType>
class RecordProcessor
{
public:
    virtual ~RecordProcessor() = 0;

    /**
     * Handle an incoming record.
     */
    virtual void handle(RecordType record) = 0;
};

/**
 * The interface's destructor.
 */
template<typename RecordType>
RecordProcessor<RecordType>::~RecordProcessor()
{
}

}


#endif
