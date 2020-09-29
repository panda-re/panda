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

#include <map>
#include <unordered_map>
#include <vector>
#include <iostream>
#include <fstream>
#include <string>
#include <jsoncpp/json/json.h>

#include "panda/plugin.h"
#include "panda/common.h"

#include "dwarf_query.h"
#include "dwarf_query_int_fns.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
}

// Globals -------------------------------------------------------------------------------------------------------------

bool log_verbose;
std::unordered_map<std::string, StructDef> struct_hashtable;
std::map<unsigned, std::string> func_hashtable;

// For CFFI ------------------------------------------------------------------------------------------------------------

// TODO: generic reader here

// Core ----------------------------------------------------------------------------------------------------------------

// Lift JSON entry to CPP class
ReadDataType member_to_rdt(const std::string& member_name, const Json::Value& member, const Json::Value& root) {

    ReadDataType rdt = ReadDataType(member_name);
    Json::Value type_category = member["type"]["kind"];

    Json::Value type_info = root["base_types"][type_category.asString()];

    if (!type_info.isNull()) {

        // Size
        rdt.size_bytes = type_info["size"].asUInt();

        // Sign
        rdt.is_signed = type_info["signed"].asBool();

        // Endianness
        rdt.is_le = (type_info["endian"].asString().compare(little_str) == 0);

        // Data type
        std::string type_kind = type_info["kind"].asString();
        if (type_kind.compare(ptr_str) == 0) {
            Json::Value sub_type = type_category["subtype"]["kind"].asString();
            assert(sub_type.compare(struct_str) == 0);
            rdt.type = DataType::STRUCT;
            rdt.is_ptr = true;
        } else if (type_kind.compare(void_str) == 0) {
            rdt.type = DataType::VOID;
        } else if (type_kind.compare(bool_str) == 0) {
            rdt.type = DataType::BOOL;
        } else if (type_kind.compare(char_str) == 0) {
            rdt.type = DataType::CHAR;
        } else if (type_kind.find(int_str) != std::string::npos) {
            rdt.type = DataType::INT;
        } else if (type_kind.find(float_str) != std::string::npos) {
            rdt.type = DataType::FLOAT;
        } else if (type_kind.find(double_str) != std::string::npos) {
            rdt.type = DataType::FLOAT;
        }

        // Explicitly mark valid
        rdt.is_valid = true;

    } else {
        fprintf(stderr, "\'%s\'!\n", member.asCString());
        std::cerr << "[WARNING] dwarf_query: Cannot parse type info for \'" << member_name << "\'" << std::endl;
        rdt.is_valid = false;
    }

    return rdt;
}

void load_struct(const std::string& struct_name, const Json::Value& struct_entry, const Json::Value& root) {

    // New struct
    StructDef sd = StructDef(struct_name);
    sd.size_bytes = struct_entry["size"].asUInt();

    // Fill struct member information
    for (auto const& member_name : struct_entry["fields"].getMemberNames()) {

        auto rdt = member_to_rdt(member_name, struct_entry["fields"][member_name], root);
        if (rdt.is_valid) {
            sd.members.push_back(rdt);
        }
    }

    if (log_verbose) {
        std::cout << "Loaded " << sd << std::endl;
    }

    // Update global hashtable
    struct_hashtable[sd.name] = sd;
}

void load_func(const std::string& func_name, const Json::Value& func_entry, const Json::Value& root) {

    if ((func_entry["type"]["kind"].asString().compare(base_str) == 0)
        && (func_entry["type"]["name"].asString().compare(void_str) == 0)) {

        unsigned addr = func_entry["address"].asUInt();
        func_hashtable[addr] = func_name;

        if (log_verbose) {
            std::cout << "Loaded func \'" << func_name << "\'@" << addr << std::endl;
        }
    }
}

void load_json(const Json::Value& root) {

    unsigned struct_cnt = 0;
    unsigned func_cnt = 0;
    std::string struct_str("struct");

    // Load struct information
    for (auto sym_name : root["user_types"].getMemberNames()) {

        Json::Value sym = root["user_types"][sym_name];

        // Skip any zero-sized types
        if (sym["size"].asUInt() > 0) {

            std::string type;

            if (!sym["kind"].isNull()) {
                type.assign(sym["kind"].asString());
            } else if (!sym["type"]["kind"].isNull()) {
                type.assign(sym["type"]["kind"].asString());
            }

            if (type.compare(struct_str) == 0) {
                load_struct(sym_name, sym, root);
                struct_cnt++;
            }

        } else {
            std::cerr << "[WARNING] dwarf_query: Skipping zero-sized type \'" << sym_name << "\'" << std::endl;
        }
    }

    // Load function information
    for (auto sym_name : root["symbols"].getMemberNames()) {
        Json::Value sym = root["symbols"][sym_name];
        load_func(sym_name, sym, root);
        func_cnt++;
    }

    std::cout << "Loaded " << func_cnt << " funcs, " << struct_cnt << "structs." << std::endl;
}

// Setup/Teardown ------------------------------------------------------------------------------------------------------

bool init_plugin(void *_self) {

    panda_arg_list *args = panda_get_args("dwarf_query");
    const char* json_filename = panda_parse_string_req(args, "json", "dwarf2json_output.json");
    log_verbose = panda_parse_bool(args, "verbose");
    std::ifstream ifs(json_filename);

    Json::Reader reader;
    Json::Value obj;

    if (!reader.parse(ifs, obj)) {
        std::cerr << "[ERROR] dwarf_query: invalid JSON!" << std::endl;
        return false;
    } else {
        load_json(obj);
    }

    switch (panda_os_familyno) {

        case OS_LINUX: {
           return true;
        } break;

        default: {
            std::cerr << "[WARNING] dwarf_query: This has never been tested for a non-Linux OS!" << std::endl;
            return true;
        }
    }
}

void uninit_plugin(void *_self) {
    // N/A
}