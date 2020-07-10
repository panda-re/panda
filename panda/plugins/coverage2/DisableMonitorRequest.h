#ifndef COVERAGE2_DISABLE_MONITOR_REQUEST_H
#define COVERAGE2_DISABLE_MONITOR_REQUEST_H

#include <memory>

#include "CoverageMode.h"
#include "MonitorRequest.h"

namespace coverage2
{

class DisableMonitorRequest : public MonitorRequest
{
public:
    DisableMonitorRequest(std::unique_ptr<CoverageMode>& m);
    void handle() override;
private:
    std::unique_ptr<CoverageMode>& mode;
};

}

#endif
