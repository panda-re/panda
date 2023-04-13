#include <stdbool.h>
#include <stdio.h>
#include <assert.h>
#include <glib.h>
#include <qemu-plugin.h>
#include <plugin-qpp.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
QEMU_PLUGIN_EXPORT const char *qemu_plugin_name = "pngsearch";

QEMU_PLUGIN_EXPORT const char *qemu_plugin_uses[] = {"stringsearch", NULL};

const uint64_t MiB = 1048576;

static uint32_t swap_u32(uint32_t val)
{
    val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF); 
    return (val << 16) | (val >> 16);
}

static uint32_t u32_be(uint64_t addr)
{
    uint32_t buf = 0;

    assert(swap_u32(0xabcd1234) == 0x3412cdab);

    qemu_plugin_read_guest_virt_mem(addr, (char*)&buf, 4);

    return swap_u32(buf);
}

static void png_header_callback(gpointer evdata, gpointer udata)
{
    uint64_t start_address = *(uint64_t*)evdata;

    uint8_t header[8] = { 0 };
    int result = qemu_plugin_read_guest_virt_mem(start_address, header, 8);

    uint64_t current_addr = start_address + 8;
    bool iend_found = false;

    while(current_addr - start_address < 128 * MiB) {
        char chunk_header[5] = { 0 };

        uint32_t chunk_len = u32_be(current_addr);
        qemu_plugin_read_guest_virt_mem(current_addr + 8, chunk_header, 4);

        current_addr = current_addr + (uint64_t)chunk_len + 0xc;

        if(memcmp(chunk_header, "IEND", 4) == 0) {
            iend_found = true;
            break;
        }
    }

    if(iend_found) {
        char name[32] = { 0 };
        snprintf(name, 31, "0x%lx.png", start_address);

        size_t output_len = snprintf(NULL, 0, "Saving to %s\n", name);
        char *output = (char*)g_malloc0(output_len + 1);

        snprintf(output, output_len, "Saving to %s\n", name);
        qemu_plugin_outs(output);

        g_free(output);

        uint64_t png_len = current_addr - start_address;

        gpointer png_buf = g_malloc(png_len);

        qemu_plugin_read_guest_virt_mem(start_address, png_buf, png_len);

        FILE *png_out = fopen(name, "wb");
        fwrite(png_buf, 1, png_len, png_out);
        fclose(png_out);
    }
}

static char PNG_MAGIC[5] = { 137, 80, 78, 71, 0 };


bool (*stringsearch_add_string)(const char* arg_str) = NULL;

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv)
{
    qemu_plugin_reg_callback("stringsearch", "on_string_found", &png_header_callback);

    stringsearch_add_string = qemu_plugin_import_function("stringsearch", "stringsearch_add_string");

    stringsearch_add_string(PNG_MAGIC);

    return 0;
}
