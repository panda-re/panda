#ifndef COVERAGE2_ASIDBLOCK_COVERAGEMODE_H
#define COVERAGE2_ASIDBLOCK_COVERAGEMODE_H

#include <fstream>
#include <string>

#include "CoverageMode.h"

namespace coverage2
{

class AsidBlockCoverageMode : public CoverageMode
{
public:
    AsidBlockCoverageMode(const std::string &filename);

    void process_block(CPUState *cpu, target_ulong pc) override;
private:
    std::ofstream output_stream;
};

}

#endif
