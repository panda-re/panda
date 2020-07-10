#include "DisableMonitorRequest.h"

namespace coverage2
{

DisableMonitorRequest::DisableMonitorRequest(std::unique_ptr<CoverageMode>& m)
    : mode(m)
{
}

void DisableMonitorRequest::handle()
{
    mode->process_results();
    mode.reset();
}

}
