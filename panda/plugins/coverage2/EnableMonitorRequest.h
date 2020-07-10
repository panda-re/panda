#ifndef COVERAGE2_ENABLE_MONITOR_REQUEST_H
#define COVERAGE2_ENABLE_MONITOR_REQUEST_H

#include <memory>
#include <string>

#include "CoverageMode.h"
#include "MonitorRequest.h"

namespace coverage2
{

class EnableMonitorRequest : public MonitorRequest
{
public:
    EnableMonitorRequest(std::unique_ptr<CoverageMode>& m, const std::string& fn);
    void handle() override;
private:
    std::unique_ptr<CoverageMode>& mode;
    std::string filename;
};

}

#endif
