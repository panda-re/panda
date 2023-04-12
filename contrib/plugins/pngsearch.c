#include <glib.h>
#include <stdio.h>
#include <qemu-plugin.h>
#include <plugin-qpp.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
QEMU_PLUGIN_EXPORT const char *qemu_plugin_name = "pngsearch";

QEMU_PLUGIN_EXPORT const char *qemu_plugin_uses[] = {"stringsearch", NULL};

static void png_header_callback(gpointer evdata, gpointer udata)
{
    uint64_t address = *(uint64_t*)evdata;

    printf("\n\naddress = 0x%lx\n\n", address);

    /* TODO: parse the PNG in order to determine if it's valid and the size to dump to the file */
}

static char PNG_HEADER[5] = { 137, 80, 78, 71, 0 };


bool (*stringsearch_add_string)(const char* arg_str) = NULL;

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv)
{
    qemu_plugin_reg_callback("stringsearch", "on_string_found", &png_header_callback);

    stringsearch_add_string = qemu_plugin_import_function("stringsearch", "stringsearch_add_string");

    stringsearch_add_string(PNG_HEADER);

    return 0;
}
