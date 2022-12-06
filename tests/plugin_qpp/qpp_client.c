#include <stdio.h>
#include <qemu-plugin.h>
#include <plugin-qpp.h>
#include <glib.h>

QEMU_PLUGIN_EXPORT const char *qemu_plugin_name = "qpp_client";
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
QEMU_PLUGIN_EXPORT const char *qemu_plugin_uses[] = {"qpp_srv", NULL};

#include "qpp_srv.h"

void my_cb_exit_callback(gpointer evdata, gpointer udata);

QEMU_PLUGIN_EXPORT void my_cb_exit_callback(gpointer evdata, gpointer udata)
{
    *(bool *)evdata = true;
    qemu_plugin_outs("called my on exit callback\n");
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                   const qemu_info_t *info, int argc, char **argv) {

    g_autoptr(GString) report = g_string_new("QPP client: Call "
                                             "qpp_srv's do_add(0) do_sub(3) => ");
    g_string_append_printf(report, "%d %d\n", qpp_srv_do_add_qpp(0),
                           qpp_srv_do_sub_qpp(3));
    qemu_plugin_outs(report->str);
    qemu_plugin_reg_callback("qpp_srv", "my_on_exit", &my_cb_exit_callback);

    return 0;
}

