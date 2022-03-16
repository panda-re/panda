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

#include "mmio_trace.h"

#include <tuple>
#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <algorithm>

const char* fn_str;
MMIOEventList mmio_events;
const char* default_dev_name = "[NONE]";

// These need to be extern "C" so that the ABI is compatible with QEMU/PANDA, which is written in C
extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
}

// CALLBACKS -----------------------------------------------------------------------------------------------------------

// PANDA_CB_MMIO_AFTER_READ callback
void buffer_mmio_read(CPUState *env, target_ptr_t physaddr, target_ptr_t vaddr, size_t size, uint64_t *val) {
    mmio_event_t new_event{'R', panda_current_pc(env), physaddr, vaddr, size, *val, default_dev_name};
    mmio_events.push_back(new_event);
    return;
}

// PANDA_CB_MMIO_BEFORE_WRITE callback
void buffer_mmio_write(CPUState *env, target_ptr_t physaddr, target_ptr_t vaddr, size_t size, uint64_t *val) {
    mmio_event_t new_event{'W', panda_current_pc(env), physaddr, vaddr, size, *val, default_dev_name};
    mmio_events.push_back(new_event);
    return;
}

// DEVICE NAME ANNOTATIONS ---------------------------------------------------------------------------------------------

// Named device range collection, helper
void add_mmio_device(MemoryRegion* mr, MMIODevList* dev_list) {
    mmio_device_t new_dev{memory_region_name(mr), mr->addr, (hwaddr)(mr->addr + mr->size)};
    (*dev_list).push_back(new_dev);
}

// Named device range collection, worker
// Creates list most-to-least specific per subtree, so later O(n) lookup will find most specific match, example:
//
//  0x0000 - 0xFFFF: system
//      0x00AA - 0x00BB: bus_1
//          0x00AD - 0x00AE: device_1
//          0x00AE - 0x00AF: device_2
//      0x00BB - 0x00CC: bus_2
//          0x00BD - 0x00BE: device_3
//          0x00BE - 0x00BF: device_4
//
//  MMIODevList -> {device_1, device_2, bus_1, device_3, device_4, bus_2, system}
void collect_mmio_dev_ranges(MemoryRegion* mr, MMIODevList* dev_list) {

    MemoryRegion *subregion;

    // Leaf hit
    if QTAILQ_EMPTY(&(mr->subregions)) {

        add_mmio_device(mr, dev_list);

    // Search children
    } else {

        QTAILQ_FOREACH(subregion, &(mr->subregions), subregions_link) {
            collect_mmio_dev_ranges(subregion, dev_list);
        }
        add_mmio_device(mr, dev_list);
    }
}

// Named device range collection, wrapper
MMIODevList get_mmio_dev_ranges(void) {

    MemoryRegion *mr = get_system_memory();
    MMIODevList dev_list;

    while (mr->container) {
        mr = mr->container;
    }

    collect_mmio_dev_ranges(mr, &dev_list);
    return dev_list;
}

// Annotate every event with the name of the corresponding MMIO device
void annotate_dev_names() {

    MMIODevList dev_list = get_mmio_dev_ranges();

    for (auto& event : mmio_events) {

        auto it = std::find_if(
            dev_list.begin(),
            dev_list.end(),
            [event](mmio_device_t dev) {
                return (dev.start_addr <= event.phys_addr) && (event.phys_addr <= dev.end_addr);
            }
        );

        if (it != dev_list.end()) {
            event.dev_name = (*it).name;
        }
    }
}

// FILE I/O ------------------------------------------------------------------------------------------------------------

// File I/O inside of a callback would be horridly slow, so we delay log flush until uninit_plugin()
void flush_to_mmio_log_file() {

    if (!fn_str) { return; }    // Pre-condition

    annotate_dev_names();

    std::ofstream out_log_file(fn_str);
    int hex_width = (sizeof(target_ulong) << 1);
    auto delim = ",\n";
    auto optional_delim = "";

    out_log_file << "[" << std::endl;

    for (auto const& event : mmio_events) {

        // Write log line, hacky JSON
        out_log_file
            << optional_delim
            << std::hex << std::setfill('0') << "{ "
            << "\"type\": \"" << event.access_type << "\", "
            << "\"guest_pc\": \"0x" << std::setw(hex_width) << event.pc << "\", "
            << "\"phys_addr\": \"0x" << std::setw(hex_width) << event.phys_addr << "\", "
            << "\"virt_addr\": \"0x" << std::setw(hex_width) << event.virt_addr << "\", "
            << "\"size\": \"0x" << std::setw(hex_width) << event.size << "\", "
            << "\"value\": \"0x" << std::setw(hex_width) << event.value << "\", "
            << "\"device\": \"" << event.dev_name << "\""
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

// C-compatible external API, caller responsible for freeing memory
mmio_event_t* get_mmio_events(int* struct_cnt_ret) {

    annotate_dev_names();

    // Note: mmio_events might be added to asynchronously as this function is executing! (but is never subtracted from)
    //  - We cannot use mmio_events.end() as a race may cause heap overflow
    //  - Instead (mmio_events.begin() + num_structs) ensures we only copy the amount present when this func read size

    // Convert and copy vector data to newly allocated heap array
    int num_structs = mmio_events.size();
    mmio_event_t* heap_arr = new mmio_event_t[num_structs];
    std::copy(mmio_events.begin(), (mmio_events.begin() + num_structs), heap_arr);

    // Provide caller with pointer to array and it's size
    *struct_cnt_ret = num_structs;
    return heap_arr;
}

// PLUGIN --------------------------------------------------------------------------------------------------------------

bool init_plugin(void* self) {

    panda_cb pcb;
    panda_arg_list* panda_args = panda_get_args("mmio_trace");

    fn_str = panda_parse_string_opt(panda_args, "out_log", nullptr, "JSON file to write MMIO trace log to.");
    if (!fn_str) {
        std::cerr << "No \'out_log\' specified, MMIO R/W will not be logged!" << std::endl;
    }

    panda_enable_precise_pc();

    pcb.mmio_after_read = buffer_mmio_read;
    panda_register_callback(self, PANDA_CB_MMIO_AFTER_READ, pcb);

    pcb.mmio_before_write = buffer_mmio_write;
    panda_register_callback(self, PANDA_CB_MMIO_BEFORE_WRITE, pcb);

    return true;
}

void uninit_plugin(void *self) {
    flush_to_mmio_log_file();
}
