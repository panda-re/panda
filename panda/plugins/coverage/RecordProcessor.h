#ifndef COVERAGE2_RECORDPROCESSOR_H
#define COVERAGE2_RECORDPROCESSOR_H

namespace coverage
{

template<typename RecordType>
class RecordProcessor
{
public:
    virtual ~RecordProcessor() = 0;
    virtual void handle(RecordType record) = 0;
};

template<typename RecordType>
RecordProcessor<RecordType>::~RecordProcessor()
{
}

}


#endif
