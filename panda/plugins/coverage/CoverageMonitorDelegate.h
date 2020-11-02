#ifndef COVERAGE_MONITOR_DELEGATE_H
#define COVERAGE_MONITOR_DELEGATE_H

#include <string>

namespace coverage
{

/**
 * An interface for handling monitor commands.
 */
class CoverageMonitorDelegate
{
public:
    virtual ~CoverageMonitorDelegate() = 0;

    virtual void handle_enable(const std::string& filename) = 0;
    virtual void handle_disable() = 0;
};

}

#endif
