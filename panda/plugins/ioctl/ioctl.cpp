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

#include "ioctl.h"

#include <tuple>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <algorithm>

const char* fn_str;
bool log_all;
UniqueIoctlsByPid pid_to_unique_ioctls;
AllIoctlsByPid pid_to_all_ioctls;

// These need to be extern "C" so that the ABI is compatible with QEMU/PANDA, which is written in C
extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
}

// FILE I/O ------------------------------------------------------------------------------------------------------------

// File I/O inside of a callback would be horridly slow, so we delay log flush until uninit_plugin()
void flush_to_ioctl_log_file() {

    if (!fn_str) { return; }    // Pre-condition

    annotate_dev_names();

    std::ofstream out_log_file(fn_str);
    int hex_width = (sizeof(target_ulong) << 1);
    auto delim = ",\n";
    auto optional_delim = "";

    out_log_file << "[" << std::endl;

    for (auto const& pid_to_ioctls : (log_all ? pid_to_all_ioctls : pid_to_unique_ioctls)) {

        auto pid = pid_to_ioctls.first;
        auto ioctls = pid_to_ioctls.second;

        for (auto const& ioctl : ioctls) {

        // Write log line, hacky JSON
        out_log_file
            << optional_delim
            << std::hex << std::setfill('0') << "{ "
            << "\"pid\": \"" << pid << "\", "
            << "\"access\": \"0x" << std::setw(hex_width) << ioctl.access << "\", "
            << "\"arg_size\": \"0x" << std::setw(hex_width) << ioctl.arg_size << "\", "
            << "\"code\": \"0x" << std::setw(hex_width) << ioctl.code << "\", "
            << "\"func_num\": \"0x" << std::setw(hex_width) << ioctl.func_num << "\", "
            << " }";

        // Validate write
        if (!out_log_file.good()) {
            std::cerr << "Error writing to " << fn_str << std::endl;
            return;
        }

        optional_delim = delim;
    }

    out_log_file << std::endl << "]" << std::endl;
    out_log_file.close();
}

// EXPORTS -------------------------------------------------------------------------------------------------------------

// TODO Decode

// TODO Command callbacks

// PLUGIN --------------------------------------------------------------------------------------------------------------

bool init_plugin(void* self) {

    panda_cb pcb;
    panda_arg_list* panda_args = panda_get_args("ioctl");

    fn_str = panda_parse_string_opt(panda_args, "out_log", nullptr, "JSON file to log unique IOCTLs by process.");
    if (!fn_str) {
        std::cerr << "No \'out_log\' specified, unique IOCTLs py process will not be logged!" << std::endl;
    }

    panda_enable_precise_pc();

    // TODO: Add flag for unique vs all

    return true;
}

void uninit_plugin(void *self) {
    flush_to_ioctl_log_file();
}