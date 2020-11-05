#ifndef COVERAGE_OSIOBSERVER_H
#define COVERAGE_OSIOBSERVER_H

#include <string>

#include "panda/plugin.h"
#include "osi/osi_types.h"

namespace coverage
{

/**
 * An interface for monitoring OS state.
 */
class OsiObserver
{
public:
    virtual ~OsiObserver() = 0;
    virtual void task_changed(const std::string& process_name,
                              target_pid_t pid,
                              target_pid_t tid) = 0;
};

}

#endif
