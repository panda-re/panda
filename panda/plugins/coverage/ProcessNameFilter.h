#ifndef COVERAGE_PROCESSNAME_PREDICATE_H
#define COVERAGE_PROCESSNAME_PREDICATE_H

#include <memory>
#include <string>

#include "osi_subject.h"
#include "OsiObserver.h"
#include "RecordProcessor.h"

namespace coverage
{

/**
 * A record processor that discards a record if the current process doesn't
 * match a given name.
 */
template<typename RecordType>
class ProcessNameFilter : public RecordProcessor<RecordType>,
                          public OsiObserver
{
public:
    ProcessNameFilter(const std::string& pname,
                      std::shared_ptr<RecordProcessor<RecordType>> del)
        : delegate(std::move(del)), target_process_name(pname), pass(false)
    {
    }

    void handle(RecordType record) override
    {
        if (pass) {
            delegate->handle(record);
        }
    }

    void task_changed(const std::string& process_name,
                      target_pid_t pid,
                      target_pid_t tid) override
    {
        pass = (target_process_name == process_name);
    }

private:
    std::shared_ptr<RecordProcessor<RecordType>> delegate;

    std::string target_process_name;
    bool pass;
};

}

#endif
