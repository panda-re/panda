#include <stdio.h>
#include <qemu-plugin.h>
#include <plugin-qpp.h>
#include <gmodule.h>
#include <assert.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
QEMU_PLUGIN_EXPORT const char *qemu_plugin_name = "qpp_srv";
#include "qpp_srv.h"

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
  qemu_plugin_outs("QPP srv: exit triggered, running all registered"
                  " QPP callbacks\n");
  bool called = false;
  qemu_plugin_run_callback(id, "my_on_exit", &called, NULL);
  assert(called);
}

QEMU_PLUGIN_EXPORT int qpp_srv_do_add(int x)
{
  return x + 1;
}

QEMU_PLUGIN_EXPORT int qpp_srv_do_sub(int x)
{
  return x - 1;
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                   const qemu_info_t *info, int argc, char **argv) {
    qemu_plugin_outs("qpp_srv loaded\n");
    qemu_plugin_create_callback(id, "my_on_exit");
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
