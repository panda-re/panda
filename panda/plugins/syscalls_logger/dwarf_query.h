#ifndef __DWARF_QUERY_H__
#define __DWARF_QUERY_H__

#include <variant>
#include <vector>
#include <string>
#include <iomanip>
#include <unordered_map>
#include <map>
#if __has_include(<jsoncpp/json/json.h>)
#include <jsoncpp/json/json.h>
#else
#include <json/json.h>
#endif

#include "panda/plugin.h"
#include "panda/common.h"

// Struct Members ------------------------------------------------------------------------------------------------------

// Typesafe union for readable primitives
typedef std::variant<
    bool,
    char,
    short int,
    int,
    long int,
    short unsigned,
    unsigned,
    long unsigned,
    float,
    double,
    long double,
    uint8_t*
> PrimitiveVariant;

// For switching on variant type (e.g. more readable variant reflection)
enum VariantType {
    VT_BOOL = 0,
    VT_CHAR = 1,
    VT_SHORT_INT = 2,
    VT_INT = 3,
    VT_LONG_INT = 4,
    VT_SHORT_UNSIGNED = 5,
    VT_UNSIGNED = 6,
    VT_LONG_UNSIGNED = 7,
    VT_FLOAT = 8,
    VT_DOUBLE = 9,
    VT_LONG_DOUBLE = 10,
    VT_UINT8_T_PTR = 11,
};

// Categorization for primitive types
enum DataType {
    VOID,   // C: void
    BOOL,   // C: bool
    CHAR,   // C: {signed, unsigned} char (sign dependant)
    INT,    // C: {signed, unsigned} {_, long, long long} int (size and sign dependant, pointers fall here)
    FLOAT,  // C: float, double, or long double (size dependant)
    STRUCT, // C: struct
    FUNC,   // C: function
    ARRAY,  // C: array of <DataType>
    UNION,  // C: union
    ENUM,   // C: enum
};

// DataType enum -> string by index, no dynamic alloc
static const char* DataTypeStrings[] = {
    "void",
    "bool",
    "char",
    "int",
    "float",
    "struct",
    "func",
    "array",
    "enum",
    "union",
};

// Information to read primitive type
// (is_ptr == true) || (is_double_ptr == true) -> pointer to described data type
class ReadableDataType {
    public:

        // Core fields (applicable to every type)
        std::string name;
        unsigned size_bytes;
        unsigned offset_bytes;
        DataType type;
        bool is_ptr;
        bool is_double_ptr;
        bool is_le;
        bool is_signed;
        bool is_valid;

        // Pointer-specific fields
        std::string ptr_trgt_name;

        // Array-specific fields
        std::string arr_member_name;
        DataType arr_member_type;
        unsigned arr_member_size_bytes;

        // Struct-specific fields
        std::string struct_name;

    // Pointer constructor (for internal use only)
    ReadableDataType(const std::string& ptr_name, const std::string& dst_name) :
        name(ptr_name), size_bytes(0), offset_bytes(0), type(DataType::VOID), is_ptr(false), is_double_ptr(false), is_le(true), is_signed(false),
        ptr_trgt_name(dst_name),
        arr_member_name("{none}"), arr_member_type(DataType::VOID), arr_member_size_bytes(0),
        struct_name("{none}") {}

    // Named type constuctor (use this most of the time)
    ReadableDataType(const std::string& type_name) : ReadableDataType(type_name, "{none}") {}

    // No-args constructor (for compiler only, don't use this)
    ReadableDataType() : ReadableDataType("{unknown}") {}

    // Get array size, returns -1 if type is not an array
    int get_arr_size() {
        if (type == DataType::ARRAY) {
            if (size_bytes) {
                assert((size_bytes % arr_member_size_bytes) == 0);
                return (size_bytes / arr_member_size_bytes);
            } else {
                return 0;
            }
        } else {
            return -1;
        }
    }

    // Get human-readable type name
    const char* get_type_name() const {
        return DataTypeStrings[type];
    }

    // Get human-readable array member type name
    const char* get_arr_member_type_name() const {
        return DataTypeStrings[arr_member_type];
    }
};

inline std::ostream & operator<<(std::ostream& os, ReadableDataType const& rdt) {

    os << std::boolalpha
        << "member \'" << rdt.name
        << "\' (offset: " << rdt.offset_bytes
        << ", type: " << rdt.get_type_name();

    if (rdt.type == DataType::STRUCT) {
        os << ", struct_name: " << rdt.struct_name;
    }

    if (rdt.type == DataType::ARRAY) {
        os << ", arr_member_name: " << rdt.arr_member_name
            << ", arr_member_type: " << rdt.get_arr_member_type_name()
            << ", arr_member_size_bytes: " << rdt.arr_member_size_bytes;
    }

    if (rdt.is_ptr || rdt.is_double_ptr) {
        os << ", ptr_trgt_name: " << rdt.ptr_trgt_name;
    }

    os << ", size: " << rdt.size_bytes
        << ", ptr: " << rdt.is_ptr
        << ", dptr: " << rdt.is_double_ptr
        << ", le: " << rdt.is_le
        << ", signed: " << rdt.is_signed
        << ", valid: " << rdt.is_valid
        << ")";

    return os;
}

// Struct --------------------------------------------------------------------------------------------------------------

class StructDef {
    public:
        std::string name;
        unsigned size_bytes;
        std::vector<ReadableDataType> members;

    StructDef(const std::string& name_in) : name(name_in), size_bytes(0) {}
    StructDef() : StructDef("{unknown}") {}
};

inline std::ostream & operator<<(std::ostream& os, StructDef const& sd) {

    os << "struct \'" << sd.name
        << "\' (size: " << sd.size_bytes
        << ", members: " << sd.members.size()
        << "):" << std::endl;

    for (auto member : sd.members) {
        os << "\t" << member << std::endl;
    }

    return os;
}

// Globals -------------------------------------------------------------------------------------------------------------

// Alloc only once, for JSON val comparison
const std::string base_str("base");
const std::string little_str("little");
const std::string ptr_str("pointer");
const std::string void_str("void");
const std::string bool_str("bool");
const std::string _Bool_str("_Bool");
const std::string char_str("char");
const std::string int_str("int");
const std::string float_str("float");
const std::string double_str("double");
const std::string struct_str("struct");
const std::string func_str("function");
const std::string array_str("array");
const std::string bitfield_str("bitfield");
const std::string enum_str("enum");
const std::string union_str("union");

// Runtime data
extern bool log_verbose;
extern std::unordered_map<std::string, StructDef> struct_hashtable;
extern std::map<unsigned, std::string> func_hashtable;

// API -----------------------------------------------------------------------------------------------------------------

// Read struct member from memory
// bool indicates read successes (account for paging errors) and type conversion success (supported readable type)
// PrimitiveVariant provides a typed copy of the data
std::pair<bool, PrimitiveVariant> read_member(CPUState *env, target_ulong addr, ReadableDataType& rdt);
void load_json(const Json::Value& root);

#endif // __DWARF_QUERY_H__
