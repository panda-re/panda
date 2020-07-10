#ifndef COVERAGE2_MONITOR_REQUEST_H
#define COVERAGE2_MONITOR_REQUEST_H

namespace coverage2
{

class MonitorRequest
{
public:
    virtual ~MonitorRequest() = 0;
    virtual void handle() = 0;
};

}

#endif
