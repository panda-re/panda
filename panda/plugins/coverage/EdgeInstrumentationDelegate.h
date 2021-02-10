#ifndef COVERAGE_EDGEINSTRUMENTATIONDELEGATE_H
#define COVERAGE_EDGEINSTRUMENTATIONDELEGATE_H

#include <memory>

#include <capstone/capstone.h>

#include "Edge.h"
#include "RecordProcessor.h"
#include "InstrumentationDelegate.h"
#include "CoverageMonitorDelegate.h"
#include "OsiObserver.h"

namespace coverage
{

struct EdgeState;

class EdgeInstrumentationDelegate : public InstrumentationDelegate,
                                    public CoverageMonitorDelegate,
                                    public OsiObserver
{
public:
    EdgeInstrumentationDelegate(std::shared_ptr<RecordProcessor<Edge>> ep);
    ~EdgeInstrumentationDelegate();

    void instrument(CPUState *cpu, TranslationBlock *tb) override;

    void handle_enable(const std::string& unused) override;
    void handle_disable() override;

    void task_changed(const std::string& process_name, target_pid_t pid, target_pid_t tid) override;

private:
    std::shared_ptr<RecordProcessor<Edge>> edge_processor;
    bool capstone_initialized;
    csh handle;
    std::unique_ptr<EdgeState> edge_state;
};

}

#endif
