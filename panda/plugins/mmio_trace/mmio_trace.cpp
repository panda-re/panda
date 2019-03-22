/* PANDABEGINCOMMENT
 *
 *  Authors:
 *  Tiemoko Ballo           N/A
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#include "panda/common.h"
#include <tuple>
#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>

const char* fn_str;
std::vector<std::tuple<char,target_ulong, int, uint64_t>> mmio_events;

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

int buffer_mmio_read(CPUState *env, target_ulong addr, int size, uint64_t val) {
    mmio_events.push_back(std::make_tuple('R', addr, size, val));
    return 0;
}

int buffer_mmio_write(CPUState *env, target_ulong addr, int size, uint64_t val) {
    mmio_events.push_back(std::make_tuple('W', addr, size, val));
    return 0;
}

// File I/O inside of a callback would be horridly slow, so we delay log flush until uninit_plugin()
void flush_to_mmio_log_file() {

    if (!fn_str) { return; }    // Pre-condition

    std::ofstream out_log_file(fn_str);
    int hex_width = (sizeof(target_ulong) << 1);

    for (auto const& entry : mmio_events) {

        // Write log line
        out_log_file
            << std::hex << std::setfill('0')
            << std::get<0>(entry) << ":"                                    // R or W
            << "0x" << std::setw(hex_width) << std::get<1>(entry) << ":"    // Physical Address
            << "0x" << std::setw(hex_width) << std::get<2>(entry) << ":"    // Size
            << "0x" << std::setw(hex_width) << std::get<3>(entry)           // Value
            << std::endl;

        // Validate write
        if (!out_log_file.good()) {
            std::cerr << "Error writing to " << fn_str << std::endl;
            return;
        }
    }
}

bool init_plugin(void* self) {

    panda_cb pcb;
    panda_arg_list* panda_args = panda_get_args("mmio_trace");

    fn_str = panda_parse_string_opt(panda_args, "out_log", nullptr, "File to write MMIO trace log to.");

    // TODO: make logging to file optional and expose MMIO data via inter-plugin API
    if (!fn_str) {
        std::cerr << "No \'out_log\' specified, MMIO R/W will not be logged!" << std::endl;
    }

    pcb.after_mmio_read = buffer_mmio_read;
    panda_register_callback(self, PANDA_CB_MMIO_AFTER_READ, pcb);

    pcb.after_mmio_write = buffer_mmio_write;
    panda_register_callback(self, PANDA_CB_MMIO_AFTER_WRITE, pcb);

    return true;
}

void uninit_plugin(void *self) {
    flush_to_mmio_log_file();
}