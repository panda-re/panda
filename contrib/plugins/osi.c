#include <stdio.h>
#include <qemu-plugin.h>
#include <plugin-qpp.h>
#include <gmodule.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
QEMU_PLUGIN_EXPORT const char *qemu_plugin_name = "osi";
#include "osi.h"

static qemu_plugin_id_t self_id;
QEMU_PLUGIN_EXPORT OsiProc *get_current_process(void) {
    OsiProc *p = NULL;
    qemu_plugin_run_callback(self_id, "on_get_current_process", &p, NULL);
    return p;
}

QEMU_PLUGIN_EXPORT OsiProc *get_process(const OsiProcHandle *h) {
    OsiProc *p = NULL; // output
    struct get_process_data* evdata = (struct get_process_data*)malloc(sizeof(struct get_process_data));
    evdata->h = h;
    evdata->p = &p;

    qemu_plugin_run_callback(self_id, "on_get_process", evdata, NULL);
    return p;
}

QEMU_PLUGIN_EXPORT OsiProcHandle *get_current_process_handle(void) {
    OsiProcHandle *h = NULL;
    qemu_plugin_run_callback(self_id, "on_get_current_process_handle", &h, NULL);
    return h;
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                   const qemu_info_t *info, int argc, char **argv) {
    self_id = id;
    qemu_plugin_outs("osi_stub loaded\n");
    qemu_plugin_create_callback(id, "on_get_current_process");
    qemu_plugin_create_callback(id, "on_get_process");
    qemu_plugin_create_callback(id, "on_get_current_process_handle");
    return 0;
}
