#ifndef COVERAGE_OSISUBJECT_H
#define COVERAGE_OSISUBJECT_H

#include "OsiObserver.h"

namespace coverage
{

void notify_task_change_observers(CPUState *cpu);

void register_osi_observer(OsiObserver* observer);

void unregister_osi_observer(OsiObserver* observer);

}

#endif
