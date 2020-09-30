#ifndef COVERAGE_EDGEINSTRUMENTATIONPASS_H
#define COVERAGE_EDGEINSTRUMENTATIONPASS_H

#include <memory>

#include <capstone/capstone.h>

#include "Edge.h"
#include "RecordProcessor.h"
#include "Pass.h"

namespace coverage
{

class EdgeInstrumentationPass : public Pass
{
public:
    EdgeInstrumentationPass(CPUState *cpu, std::unique_ptr<RecordProcessor<Edge>> ep);
    ~EdgeInstrumentationPass();

    void before_tcg_codegen(CPUState *cpu, TranslationBlock *tb) override;
private:
    std::unique_ptr<RecordProcessor<Edge>> edge_processor;
    csh handle;
};

}

#endif
