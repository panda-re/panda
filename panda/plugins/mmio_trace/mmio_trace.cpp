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

#include "mmio_trace.h" // mmio_event_t, panda imports
#include <tuple>
#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>

const char* fn_str;
std::vector<mmio_event_t> mmio_events;

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

int buffer_mmio_read(CPUState *env, target_ulong addr, int size, uint64_t val) {
    mmio_event_t new_event{'W', addr, size, val};
    mmio_events.push_back(new_event);
    return 0;
}

int buffer_mmio_write(CPUState *env, target_ulong addr, int size, uint64_t val) {
    mmio_event_t new_event{'R', addr, size, val};
    mmio_events.push_back(new_event);
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
            << entry.access_type << ":"                                     // R or W
            << "0x" << std::setw(hex_width) << entry.phys_addr << ":"       // Physical Address
            << "0x" << std::setw(hex_width) << entry.size << ":"            // Size
            << "0x" << std::setw(hex_width) << entry.value                  // Value
            << std::endl;

        // Validate write
        if (!out_log_file.good()) {
            std::cerr << "Error writing to " << fn_str << std::endl;
            return;
        }
    }
}

// C-compatible external API, caller responsible for freeing memory
mmio_event_t* get_mmio_events(int* arr_size_ret) {

    // Note: mmio_events might be added to asynchronously as this function is executing!
    //  - We cannot use mmio_events.end() as a race may cause heap overflow
    //  - Instead (mmio_events.begin() + num_structs) ensures we only copy the amount present when this func read size

    // Copy vector data to newly allocated heap array
    int num_structs = mmio_events.size();
    mmio_event_t* heap_arr = new mmio_event_t[num_structs];
    std::copy(mmio_events.begin(), (mmio_events.begin() + num_structs), heap_arr);

    // Provide caller with pointer to array and it's size
    *arr_size_ret = num_structs;
    return heap_arr;
}

bool init_plugin(void* self) {

    panda_cb pcb;
    panda_arg_list* panda_args = panda_get_args("mmio_trace");

    fn_str = panda_parse_string_opt(panda_args, "out_log", nullptr, "File to write MMIO trace log to.");
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