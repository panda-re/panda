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

static void task_change_callback(CPUState *cpu)
{
    std::unique_ptr<OsiProc, decltype(free_osiproc)*> current_process(get_current_process(cpu), free_osiproc);
    std::unique_ptr<OsiThread, decltype(free_osithread)*> current_thread(get_current_thread(cpu), free_osithread);

    for (auto ob : observers) {
        ob->task_changed(current_process->name, current_thread->pid, current_thread->tid);
    }
}

void register_osi_observer(OsiObserver* observer)
{
    if (!callbacks_registered) {
        panda_require("osi");
        assert(init_osi_api());
        PPP_REG_CB("osi", on_task_change, task_change_callback);
        callbacks_registered = true;
    }
    observers.push_back(observer);
}

}
