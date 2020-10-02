#ifndef __DWARF_QUERY_H__
#define __DWARF_QUERY_H__

#include <vector>
#include <string>
#include <iomanip>

// Alloc only once, for JSON val comparison
const std::string base_str("base");
const std::string little_str("little");
const std::string ptr_str("pointer");
const std::string void_str("void");
const std::string bool_str("bool");
const std::string char_str("char");
const std::string int_str("int");
const std::string float_str("float");
const std::string double_str("double");
const std::string struct_str("struct");
const std::string func_str("function");
const std::string array_str("array");
const std::string bitfield_str("bitfield");
const std::string enum_str("enum");

// Categorization for primitive types
enum DataType {
    VOID,   // C: void
    BOOL,   // C: bool
    CHAR,   // C: {signed, unsigned} char (sign dependant)
    INT,    // C: {signed, unsigned} {_, long, long long} int (size and sign dependant)
    FLOAT,  // C: float, double, or long double (size dependant)
    STRUCT, // C: struct
    FUNC,   // C: function
};

// Information to read primitive type
// (is_ptr == true) -> pointer to described data type
class ReadDataType {
    public:
        std::string name;
        std::string ptr_trgt_name;
        unsigned size_bytes;
        unsigned offset_bytes;
        DataType type;
        bool is_ptr;
        bool is_double_ptr;
        bool is_le;
        bool is_signed;
        bool is_valid;

    ReadDataType(const std::string& ptr_name, const std::string& dst_name) : name(ptr_name), ptr_trgt_name(dst_name),
        size_bytes(0), offset_bytes(0), type(DataType::VOID), is_ptr(false), is_double_ptr(false), is_le(true), is_signed(false) {}

    ReadDataType(const std::string& type_name) : ReadDataType(type_name, "{none}") {}

    ReadDataType() : ReadDataType("{unknown}") {}
};

inline std::ostream & operator<<(std::ostream& os, ReadDataType const& rdt) {

    std::string type;
    switch(rdt.type) {
        case DataType::VOID:
            type.assign("void");
            break;
        case DataType::BOOL:
            type.assign("bool");
            break;
        case DataType::CHAR:
            type.assign("char");
            break;
        case DataType::INT:
            type.assign("int");
            break;
        case DataType::FLOAT:
            type.assign("float");
            break;
        case DataType::STRUCT:
            type.assign("struct");
            break;
        case DataType::FUNC:
            type.assign("function");
            break;
        default:
            type.assign("{unknown}");
            break;
    }

    os << std::boolalpha
        << "member \'" << rdt.name
        << "\' (offset: " << rdt.offset_bytes
        << ", type: " << type
        << ", size: " << rdt.size_bytes
        << ", ptr: " << rdt.is_ptr
        << ", le: " << rdt.is_le
        << ", signed: " << rdt.is_signed
        << ", valid: " << rdt.is_valid
        << ")";

    return os;
}

class StructDef {
    public:
        std::string name;
        unsigned size_bytes;
        std::vector<ReadDataType> members;

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

#endif // __DWARF_QUERY_H__