
#ifndef __WINTROSPECTION_H__
#define __WINTROSPECTION_H__


typedef struct handle_object_struct {
    uint8_t objType;
    uint32_t pObj;
} HandleObject;


// See: https://msdn.microsoft.com/en-us/library/windows/desktop/aa380518(v=vs.85).aspx
typedef struct {
    uint16_t Length;        // length excluding terminator in bytes
    uint16_t MaximumLength; // allocated memory for buffer
    target_ulong Buffer;    // pointer to allocated memory
} win_unicode_string_t;

// Size of guest pointer.
// Note that this can't just be target_ulong since
// a 32-bit OS will run on x86_64-softmmu
// To add support for a 64-bit OS, consider creating a wintrospection64 plugin.
#define PTR uint32_t

#define HANDLE_MASK1  0x000007fc
#define HANDLE_SHIFT1 2
#define HANDLE_MASK2  0x001ff800
#define HANDLE_SHIFT2  11
#define HANDLE_MASK3  0x7fe00000
#define HANDLE_SHIFT3  21
#define LEVEL_MASK 0x00000007
#define TABLE_MASK ~LEVEL_MASK
#define ADDR_SIZE 4
#define HANDLE_TABLE_ENTRY_SIZE 8

#endif

