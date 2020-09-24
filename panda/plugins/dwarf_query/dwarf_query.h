#ifndef __DWARF_QUERY_H__
#define __DWARF_QUERY_H__

// Widths based on 64-bit host, not guest sizes
enum DataType {
    BOOL,
    CHAR,
    DOUBLE,
    SHORT_INT,
    INT,
    LONG_INT,
    LONG_LONG_INT,
    SHORT_UNSIGNED,
    UNSIGNED,
    LONG_UNSIGNED,
    LONG_LONG_UNSIGNED,
};

struct ReadDataType {
    DataType type;
    bool is_le;
};

#endif __DWARF_QUERY_H__