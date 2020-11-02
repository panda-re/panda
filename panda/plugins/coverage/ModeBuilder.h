#ifndef COVERAGE_MODE_BUILDER_H
#define COVERAGE_MODE_BUILDER_H

#include <memory>
#include <string>
#include <vector>

#include "CoverageMonitorDelegate.h"
#include "InstrumentationDelegate.h"

namespace coverage
{

class ModeBuilder
{
public:
    ModeBuilder(std::vector<CoverageMonitorDelegate *>& mds);

    ModeBuilder& with_mode(const std::string& mode);
    ModeBuilder& with_process_name_filter(const std::string& pname);
    ModeBuilder& with_filename(const std::string& filename);
    ModeBuilder& with_unique_filter();

    std::unique_ptr<InstrumentationDelegate> build();

private:
    std::vector<CoverageMonitorDelegate *>& monitor_delegates;

    std::string mode;
    std::string process_name;
    std::string filename;
    bool unique;
};

}

#endif
