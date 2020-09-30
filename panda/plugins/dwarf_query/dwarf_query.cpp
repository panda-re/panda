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
#include <algorithm>
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

// TODO: handle UNIONS

DataType str_to_dt(std::string const& kind) {
    if (kind.compare(void_str) == 0) {
        return DataType::VOID;
    } else if (kind.compare(bool_str) == 0) {
        return DataType::BOOL;
    } else if (kind.compare(char_str) == 0) {
        return DataType::CHAR;
    } else if (kind.find(int_str) != std::string::npos) {
        return DataType::INT;
    } else if (kind.find(float_str) != std::string::npos) {
        return DataType::FLOAT;
    } else if (kind.find(double_str) != std::string::npos) {
        return DataType::FLOAT;
    } else if (kind.compare(struct_str) == 0) {
        return DataType::STRUCT;
    } else if (kind.compare(func_str) == 0) {
        return DataType::FUNC;
    } else {
        std::cerr << "[FATAL ERROR] dwarf_query: Unknown kind \'" << kind << "\', no mapping to DataType!" << std::endl;
        assert(false);
    }
}

// Lift JSON entry to CPP class
ReadDataType member_to_rdt(const std::string& member_name, const Json::Value& member, const Json::Value& root) {

    // TODO: remove debug print
    //printf("DEBUG: %s\n", member_name.c_str());

    ReadDataType rdt = ReadDataType(member_name);
    Json::Value type_category = member["type"]["kind"];
    Json::Value type_name = member["type"]["name"];
    Json::Value type_info = root["base_types"][type_name.asString()];

    bool ptr_type = (type_category.asString().compare(ptr_str) == 0);
    bool struct_type = (type_category.asString().compare(struct_str) == 0);
    bool array_type = (type_category.asString().compare(array_str) == 0);
    assert((ptr_type + struct_type + array_type) <= 1);

    // Offset
    rdt.offset_bytes = member["offset"].asUInt();

    // Embedded struct
    if (struct_type) {

        rdt.size_bytes = root["user_types"][member_name]["size"].asUInt();
        rdt.is_le = (root["base_types"]["pointer"]["endian"].asString().compare(little_str) == 0);
        rdt.type = DataType::STRUCT;
        rdt.is_ptr = false;
        rdt.is_signed = false;
        rdt.is_valid = true;

    // Embedded Array {
    } else if (array_type) {

        // TODO: add array support
        std::cerr << "[WARNING] dwarf_query: array support not yet implemented, skipping member \'" << member_name << "\'" << std::endl;

    // Struct pointer, function pointer, or primitive datatype
    } else {

        // TODO: support arrays!

        // Pointer
        if (ptr_type) {

            Json::Value subtype_kind = member["type"]["subtype"]["kind"];
            Json::Value subtype_name = member["type"]["subtype"]["name"];

            // TODO: temp debug
            printf("DEBUG (%s): %s -> %s\n", member_name.c_str(), subtype_kind.asString().c_str(), struct_str.c_str());

            bool struct_ptr = (subtype_kind.asString().compare(struct_str) == 0);
            bool func_ptr = (subtype_kind.asString().compare(func_str) == 0);

            bool void_ptr = (subtype_kind.asString().compare(base_str) == 0)
                && (subtype_name.asString().compare(void_str) == 0);

            bool prim_ptr = (subtype_kind.asString().compare(base_str) == 0)
                && (!(root["base_types"][subtype_name.asString()].isNull()))
                && (subtype_name.asString().compare(void_str) != 0);

            assert((struct_ptr + func_ptr + void_ptr + prim_ptr) == 1);

            if (struct_ptr) {
                rdt.type = DataType::STRUCT;
            } else if (func_ptr) {
                rdt.type = DataType::FUNC;
            } else if (void_ptr) {
                rdt.type = DataType::VOID;
            } else if (prim_ptr) {
                std::string prim_name = subtype_name.asString();
                rdt.type = str_to_dt(prim_name);
            }

            type_info = root["base_types"][type_category.asString()];
            rdt.is_ptr = true;

        // Primitive type
        } else {
            std::string kind = type_info["kind"].asString();
            rdt.is_ptr = false;
            rdt.type = str_to_dt(kind);
        }

        // Metadata for pointers and primitives
        if (!type_info.isNull()) {
            rdt.size_bytes = type_info["size"].asUInt();
            rdt.is_signed = type_info["signed"].asBool();
            rdt.is_le = (type_info["endian"].asString().compare(little_str) == 0);
            rdt.is_valid = true;
        } else {
            std::cerr << "[WARNING] dwarf_query: Cannot parse type info for \'" << member_name << "\'" << std::endl;
            rdt.is_valid = false;
        }
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

    // Sort by offset
    std::sort(
        sd.members.begin(),
        sd.members.end(),
        [](const ReadDataType& x, const ReadDataType& y) { return x.offset_bytes < y.offset_bytes; }
    );

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

            // TODO: verify this is neccessary/correct?
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