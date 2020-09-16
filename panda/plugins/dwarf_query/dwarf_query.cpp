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

#include <iostream>
#include <fstream>
#include <jsoncpp/json/json.h>

#include "panda/plugin.h"
#include "panda/common.h"

#include "dwarf_query_int_fns.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
}

// Globals -------------------------------------------------------------------------------------------------------------

Json::Reader reader;
Json::Value obj;

// Python CFFI API -----------------------------------------------------------------------------------------------------

// TODO

// Core ----------------------------------------------------------------------------------------------------------------

// TODO

// Setup/Teardown ------------------------------------------------------------------------------------------------------

bool init_plugin(void *_self) {

    if (!pandalog) {
        fprintf(stderr, "[ERROR] dwarf_query: Set with -pandalog [filename]\n");
        return  false;
    }

    panda_arg_list *args = panda_get_args("dwarf_query");
    const char* json_filename = panda_parse_string(args, "json", "dwarf2json_output.json");
    std::ifstream ifs(json_filename);

    switch (panda_os_familyno) {

        case OS_LINUX: {
           return reader.parse(ifs, obj);
        } break;

        default: {
            fprintf(stderr, "[WARNING] dwarf_query: This has never been tested for a non-Linux OS!\n");
            return reader.parse(ifs, obj);
        }
    }
}

void uninit_plugin(void *_self) {
    // N/A
}