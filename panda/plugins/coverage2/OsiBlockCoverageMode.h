#ifndef COVERAGE2_OSIBLOCK_COVERAGEMODE_H
#define COVERAGE2_OSIBLOCK_COVERAGEMODE_H

#include <fstream>
#include <string>

#include "CoverageMode.h"

namespace coverage2
{

class OsiBlockCoverageMode : public CoverageMode
{
public:
    OsiBlockCoverageMode(const std::string &filename);

    void process_block(CPUState *cpu, TranslationBlock *tb) override;

    void process_results() override;
private:
    std::ofstream output_stream;
};

}

#endif
