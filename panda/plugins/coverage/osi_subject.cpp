#include <algorithm>
#include <memory>
#include <vector>

#include "panda/plugin.h"

#include "osi/osi_types.h"
#include "osi/osi_ext.h"
#include "osi/os_intro.h"

#include "osi_subject.h"
#include "OsiObserver.h"

namespace coverage
{

static bool callbacks_registered = false;
static std::vector<OsiObserver*> observers;

void notify_task_change_observers(CPUState *cpu)
{
    if (observers.empty()) {
        return;
    }

    std::unique_ptr<OsiProc, decltype(free_osiproc)*> current_process(get_current_process(cpu), free_osiproc);
    std::unique_ptr<OsiThread, decltype(free_osithread)*> current_thread(get_current_thread(cpu), free_osithread);

    for (auto ob : observers) {
        ob->task_changed(
            nullptr == current_process ? "(unknown)" : current_process->name,
            nullptr == current_thread  ? 0 : current_thread->pid,
            nullptr == current_thread  ? 0 : current_thread->tid);
    }
}

void register_osi_observer(OsiObserver* observer)
{
    if (!callbacks_registered) {
        panda_require("osi");
        assert(init_osi_api());
        PPP_REG_CB("osi", on_task_change, notify_task_change_observers);
        callbacks_registered = true;
    }
    observers.push_back(observer);
}

void unregister_osi_observer(OsiObserver* observer) {
    auto it = std::find(observers.begin(), observers.end(), observer);
    if (observers.end() != it) {
        observers.erase(it);
    }
}

}
