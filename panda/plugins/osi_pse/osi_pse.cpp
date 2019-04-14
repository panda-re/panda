/*!
 * @file osi_pse.cpp
 * @brief Process-level events using the osi plugin.
 *
 * @author Manolis Stamatogiannakis manolis.stamatogiannakis@vu.nl
 *
 * @copyright This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 */
#include <glib.h>
#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include "panda/common.h"

// osi plugin
#include "osi/osi_types.h"
#include "osi/os_intro.h"
#include "osi/osi_ext.h"

// syscalls2 plugin
#include "syscalls2/syscalls_ext_typedefs.h"
#include "syscalls2/syscalls2_info.h"
#include "syscalls2/syscalls2_ext.h"

// callback types
#include "osi_pse.h"

extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
bool init_osi_pse_linux(void *);
void uninit_osi_pse_linux(void *);
bool init_osi_pse_generic(void *);
void uninit_osi_pse_generic(void *);
PPP_PROT_REG_CB(on_process_start)
PPP_PROT_REG_CB(on_process_end)
}
PPP_CB_BOILERPLATE(on_process_start)
PPP_CB_BOILERPLATE(on_process_end)


bool init_plugin(void *self) {
    panda_require("osi");
    if (!init_osi_api()) {
        return false;
    }
    panda_require("syscalls2");
    if (!init_syscalls2_api()) {
        return false;
    }
    if (panda_os_familyno == OS_LINUX) {
        if (!init_osi_pse_linux(self)) {
            return false;
        }
    } else {
        LOG_WARNING("Plugin has not been tested with %s!!!", panda_os_family);
        LOG_WARNING("Continuing anyway with generic implementation.");
#if 0
        if (!init_osi_pse_generic(self)) {
            return false;
        }
#else
        return false;
#endif
    }

    LOG_INFO(PLUGIN_NAME " initialization complete.");
    return true;
}

void uninit_plugin(void *self) {
    if (panda_os_familyno == OS_LINUX) {
        uninit_osi_pse_linux(self);
    } else {
#if 0
        uninit_osi_pse_generic(self);
#endif
    }
    LOG_INFO(PLUGIN_NAME " cleanup complete.");
}


/* vim:set tabstop=4 softtabstop=4 expandtab: */
