#ifndef COVERAGE_OSIBLOCK_GENERATOR_H
#define COVERAGE_OSIBLOCK_GENERATOR_H

#include <memory>

#include "OsiObserver.h"
#include "OsiBlock.h"
#include "RecordProcessor.h"

namespace coverage
{

/**
 * Transforms a regular Block struct into an OsiBlock.
 */
class OsiBlockGenerator : public RecordProcessor<Block>,
                          public OsiObserver
{
public:
    OsiBlockGenerator(std::shared_ptr<RecordProcessor<OsiBlock>> d);
    void handle(Block record) override;

    void task_changed(const std::string& process_name, target_pid_t pid, target_pid_t tid) override;
private:
    std::string pname;
    target_pid_t pid;
    target_pid_t tid;
    std::shared_ptr<RecordProcessor<OsiBlock>> delegate;
};

}

#endif
