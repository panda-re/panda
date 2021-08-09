/* PANDABEGINCOMMENT
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <memory>
#include <string>
#include <unordered_map>
#include <iostream>
#include <fstream>

#include "panda/plugin.h"

#include "syscalls2/syscalls_ext_typedefs.h"
#include "syscalls2/syscalls2_info.h"
#include "syscalls2/syscalls2_ext.h"

#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include "osi_linux/osi_linux_ext.h"

#include "dwarf_query.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
}

// TODO: make these optional commandline params
#define MAX_STRLEN 1024
#define STRUCT_RECURSION_LIMIT 256

std::vector<void*> tmp_single_ptrs;
std::vector<void*> tmp_double_ptrs;
bool did_call_warning;
const char* target_process = NULL;
target_ulong last_pid = 0;

// Read a string from guest memory
int get_string(CPUState *cpu, target_ulong addr, uint8_t *buf) {
    // determine strlen (upto max)
    int len = 0;
    uint8_t c;
    while (len < MAX_STRLEN) {
        int rv = panda_virtual_memory_read(cpu, addr + len, (uint8_t*) (&c), 1);
        if (rv == -1) break;
        if (c == 0) break;
        len++;
    }
    if (len > 0) {
        int rv = panda_virtual_memory_read(cpu, addr, (uint8_t*) buf, len);
        buf[len] = 0;
        for (int i = 0; i < len; i++)
            if (!isprint(buf[i])) buf[i] = '.';
        assert(rv != -1);
    }
    return len;
}

int is_likely_string(CPUState *cpu, target_ulong addr) {
    // Returns strlen or -1 if unlikely to be a string
    int len = 0;
    uint8_t buf[MAX_STRLEN];
    while (len < MAX_STRLEN) {
        int rv = panda_virtual_memory_read(cpu, addr + len, (uint8_t*) (buf+len), 1);
        if (rv == -1) break;
        if (buf[len] == 0) break;
        len++;
    }

    // We just read up to len with no null bytes - If they're all printable we return len
    int printable_count = 0;
    for (int i=0; i < len; i++) {
        if (std::isprint(buf[i])) {
            printable_count++;
        }else{
            break;
        }
    }
    // Keeping this as a seprate loop so we can tune it to something other than 100% printable if we want
    // if all printable up to null, say it's a string. if it's a null byte that's printable (empty string)
    if (len==printable_count) {
        return len;
    }
    return -1;
}

void get_n_buf(CPUState *cpu, target_ulong addr, uint8_t *buf, uint64_t size) {
    // Populate buf with data at addr of the provided size

    uint8_t* dest;

    // Read buffer, one character at a time (slower than a big read, but can handle failures)
    //
    for (int len=0; len < size; len++) {

        dest = &buf[len];

        if (panda_virtual_memory_read(cpu, addr + len, dest, 1) == -1) {
            // read failed
            buf[len] = '.'; // Might also want to warn that data is unavailable
        //}else if (!isprint(buf[len])) {
            //buf[len] = '.'; // Only printable characters?
        }
    }
}

// Validate string
bool check_str(char* s) {
    for (int i = 0; i < MAX_STRLEN; i++) {
        if ((s[i] == 0) && (i > 0)) {
            break;
        }

        if (!isprint(s[i])) {
            return false;
        }

        if ((i == (MAX_STRLEN - 1)) && (s[i] != 0)) {
            return false;
        }
    }
    return true;
}

// Read a pointer from guest memory
target_ulong get_ptr(CPUState *cpu, target_ulong addr) {
    target_ulong ptr;
    if (panda_virtual_memory_read(cpu, addr, (uint8_t*)&ptr, sizeof(target_ulong)) != 0) {
        ptr = 0;
    }
    return ptr;
}

// Parse out primitive array buffers
Panda__StructData* array_logger(ReadableDataType& rdt, PrimitiveVariant& data, bool pandalog) {

    uint8_t* buf = std::get<uint8_t*>(data);
    int arr_size = rdt.get_arr_size();

    if (arr_size <= 0) {
        return 0;
    }

    Panda__StructData *sdata = NULL;

    if (pandalog) {
        sdata = (Panda__StructData*)malloc(sizeof(Panda__StructData));
        assert(sdata != NULL);
        tmp_single_ptrs.push_back(sdata);
        *sdata = PANDA__STRUCT_DATA__INIT;

        Panda__NamedData**  members = (Panda__NamedData **)malloc(sizeof(Panda__NamedData *) * arr_size);
        assert(members != NULL);
        tmp_double_ptrs.push_back(members);
        sdata->members = members;
    }

    for (int i = 0; i < arr_size; i++) {

        uint8_t* data_ptr = buf + (i * rdt.arr_member_size_bytes);

        Panda__NamedData *m = NULL;
        if (pandalog) {
            m = (Panda__NamedData *)malloc(sizeof(Panda__NamedData));
            assert(m != NULL);
            tmp_single_ptrs.push_back(m);

            sdata->members[i] = m;
            *m = PANDA__NAMED_DATA__INIT;
        }

        switch (rdt.arr_member_type) {
            case DataType::BOOL:
            case DataType::INT:
                if (rdt.is_signed) {
                    switch (rdt.size_bytes) {
                        case sizeof(short int):
                            if (pandalog) {
                                m->i16 = *(short int*)data_ptr;
                                m->has_i16 = true;
                            }else{
                                std::cout << *(short int*)data_ptr;
                            }
                            break;
                        case sizeof(int):
                            if (pandalog) {
                                m->i32 = *(int*)data_ptr;
                                m->has_i32 = true;
                            }else{
                                std::cout << *(int*)data_ptr;
                            }
                            break;
                        case sizeof(long int):
                            if (pandalog) {
                                m->i64 = *(long int*)data_ptr;
                                m->has_i64 = true;
                            }else{
                                std::cout << *(long int*)data_ptr;
                            }
                            break;
                        default:
                            return 0;
                            break;
                    }
                } else {
                    switch (rdt.size_bytes) {
                        case sizeof(short unsigned):
                            if (pandalog) {
                                m->u16 = *(short unsigned*)data_ptr;
                                m->has_u16 = true;
                            }else{
                                std::cout << *(short unsigned*)data_ptr;
                            }
                            break;
                        case sizeof(unsigned):
                            if (pandalog) {
                                m->u32 = *(unsigned*)data_ptr;
                                m->has_u32 = true;
                            }else{
                                std::cout << *(unsigned*)data_ptr;
                            }
                            break;
                        case sizeof(long unsigned):
                            if (pandalog) {
                                m->u64 = *(long unsigned*)data_ptr;
                                m->has_u64 = true;
                            }else{
                                std::cout << *(long unsigned*)data_ptr;
                            }
                            break;
                        default:
                            return 0;
                            break;
                    }
                }
                break;

            case DataType::FLOAT:
                switch (rdt.size_bytes) {
                    case sizeof(float):
                        if (pandalog) {
                            m->float_val = *(float*)data_ptr;
                            m->has_float_val = true;
                        }else{
                            std::cout << *(float*)data_ptr;
                        }
                        break;
                    case sizeof(double):
                        if (pandalog) {
                            m->double_val = *(float*)data_ptr;
                            m->has_double_val = true;
                        }else{
                            std::cout << *(double*)data_ptr; // Note we actually read a double for ptinting while logging uses a float
                        }
                        break;
                    default:
                        return 0;
                        break;
                }
            default:
                return 0;
                break;
        }
    }

    if (pandalog) {
        sdata->n_members = arr_size;
        return sdata;
    }
    return NULL;
}

// Helper for struct_logger
void set_data(Panda__NamedData* nd, ReadableDataType& rdt, PrimitiveVariant& data) {
    switch (data.index()) {
        case VariantType::VT_BOOL:
            if (nd) {
                nd->bool_val = std::get<bool>(data);
                nd->has_bool_val = true;
            }else{
                std::cout << std::get<bool>(data);
            }
            break;
        case VariantType::VT_CHAR:
            {
                if (nd) {
                    static_assert(sizeof(char) == 1);
                    std::string char_str(1, std::get<char>(data));
                    nd->str = strdup(char_str.c_str());
                }else{
                    std::cout << std::get<char>(data);
                }
            }
            break;
        case VariantType::VT_SHORT_INT:
            if (nd) {
                static_assert(sizeof(short int) == 2);
                nd->i16 = std::get<short int>(data);
                nd->has_i16 = true;
            }else{
                std::cout << std::get<short int>(data);
            }
            break;
        case VariantType::VT_INT:
            if (nd) {
                static_assert(sizeof(int) == 4);
                nd->i32 = std::get<int>(data);
                nd->has_i32 = true;
            }else{
                std::cout << std::get<int>(data);
            }
            break;
        case VariantType::VT_LONG_INT:
            if (nd) {
                static_assert(sizeof(long int) == 8);
                nd->i64 = std::get<long int>(data);
                nd->has_i64 = true;
            }else{
                std::cout << std::get<long int>(data);
            }
            break;
        case VariantType::VT_SHORT_UNSIGNED:
            if (nd) {
                static_assert(sizeof(short unsigned) == 2);
                nd->u16 = std::get<short unsigned>(data);
                nd->has_u16 = true;
            }else{
                std::cout << std::get<short unsigned>(data);
            }
            break;
        case VariantType::VT_UNSIGNED:
            if (nd) {
                static_assert(sizeof(unsigned) == 4);
                nd->u32 = std::get<unsigned>(data);
                nd->has_u32 = true;
            }else{
                std::cout << std::get<unsigned>(data);
            }
            break;
        case VariantType::VT_LONG_UNSIGNED:
            if (nd) {
                static_assert(sizeof(long unsigned) == 8);
                nd->u64 = std::get<long unsigned>(data);
                nd->has_u64 = true;
            }else{
                std::cout << std::get<long unsigned>(data);
            }
            break;
        case VariantType::VT_FLOAT:
            if (nd) {
                nd->float_val = std::get<float>(data);
                nd->has_float_val = true;
            }else{
                std::cout << std::get<float>(data);
            }
            break;
        case VariantType::VT_DOUBLE:
            if (nd) {
                nd->double_val = std::get<double>(data);
                nd->has_double_val = true;
            }else{
                std::cout << std::get<double>(data);
            }
            break;
        case VariantType::VT_LONG_DOUBLE:
            if (nd) {
                nd->double_val = (double)std::get<long double>(data);
                nd->has_double_val = true;
                std::cerr << "[WARNING] syscalls_logger: casting long double to double (only latter supported by protobuf)" << std::endl;
            }else{
                std::cout << std::get<long double>(data);
            }
            break;
        case VariantType::VT_UINT8_T_PTR:
        {
            char* str_ptr = (char *)std::get<uint8_t*>(data);
            if ((rdt.type == DataType::ARRAY) && (rdt.arr_member_type == DataType::CHAR) && check_str(str_ptr)) {
                if (nd) {
                    nd->str = strdup(str_ptr);
                }else{
                    std::cout << str_ptr; // Not sure about this one
                }
                return;
            } else if ((rdt.type == DataType::ARRAY) && (rdt.arr_member_type != DataType::CHAR)) {
                auto sdata = array_logger(rdt, data, nd!=NULL);
                if (sdata) {
                    if (nd) {
                        nd->struct_type = strdup("ArrayOfPrimitive");
                        nd->struct_data = sdata;
                    }
                    return;
                }
            }

            assert(rdt.type != DataType::STRUCT);
            // TODO: how to convert to protobuf bytes? This is a host pointer, not helpful
            if (nd) {
                nd->ptr = (uint64_t)std::get<uint8_t*>(data);
                nd->has_ptr = true;
            }else{
                std::cout << std::get<uint8_t*>(data); // Not sure about this one
            }
            break;
        }
        default:
            assert(false && "FATAL: default case should never hit, function \"set_data()\"");
            break;
    }
}

// TODO: reduce code repetition in recursive cases
// Recursively read struct information for PANDALOG, using DWARF layout information
Panda__StructData* struct_logger(CPUState *cpu, target_ulong saddr, StructDef& sdef, bool pandalog, int recursion_limit) {
    // Here we analyze the DWARFINFO we have to determine the type of a struct

    int mcount = sdef.members.size();

    if (saddr == 0) {
        // Null pointer - if logging to pandalog, return NULL
        // or if logging to stdout write NULL

        if (!pandalog) {
            std::cout << "NULL";
        }
        return NULL;
    }

    Panda__StructData *sdata = NULL;

    if (pandalog) {
        sdata = (Panda__StructData*)malloc(sizeof(Panda__StructData));
        assert(sdata != NULL);
        tmp_single_ptrs.push_back(sdata);
        *sdata = PANDA__STRUCT_DATA__INIT;

        Panda__NamedData**  members = (Panda__NamedData **)malloc(sizeof(Panda__NamedData *) * mcount);
        assert(members != NULL);
        tmp_double_ptrs.push_back(members);
        sdata->members = members;
    } else {
        std::cout << "{";
    }

    for (int i = 0; i < mcount; i++) {
        Panda__NamedData *m = NULL;
        ReadableDataType mdef = sdef.members[i];
        target_ulong maddr = saddr + mdef.offset_bytes;

        if (mdef.name.find(std::string("__unused")) != std::string::npos || mdef.name.find(std::string("__pad")) != std::string::npos) {
            // some names we get from the dwarf info are __unusedX and we don't really want to log those
            continue;
        }

        if (pandalog) {
            m = (Panda__NamedData *)malloc(sizeof(Panda__NamedData));
            assert(m != NULL);
            tmp_single_ptrs.push_back(m);

            sdata->members[i] = m;
            *m = PANDA__NAMED_DATA__INIT;
            m->arg_name = strdup(mdef.name.c_str());
        }else{
            if (i > 0) {
                std::cout << ", ";
            }
            std::cout << mdef.name << "=";
        }

        if (log_verbose) {
            std::cout << "[INFO] syscalls_logger: loading struct " << sdef.name
                << ", member: " << mdef.name
                << ", addr: 0x" << std::hex << maddr << std::dec << std::endl;
        }


        std::string error;
        // Recursive - member is embedded struct
        if ((mdef.type == DataType::STRUCT) && (mdef.is_ptr == false)) {

            auto it = struct_hashtable.find(mdef.struct_name);

            if ((recursion_limit > 0) && it != struct_hashtable.end() && (sdef.name.compare(mdef.struct_name) != 0)) {
                if (pandalog) {
                    m->struct_type = strdup(mdef.struct_name.c_str());
                    m->struct_data = struct_logger(cpu, maddr, it->second, pandalog, (recursion_limit - 1));
                } else {
                    struct_logger(cpu, maddr, it->second, pandalog, (recursion_limit - 1));
                }
            } else {
                error ="read failed, unknown embeddded struct (embedded struct)";
            }

        // Recursive - member is pointer to struct
        } else if ((mdef.type == DataType::STRUCT) && (mdef.is_ptr == true) && (mdef.is_double_ptr == false)) {

            auto it = struct_hashtable.find(mdef.struct_name);
            target_ulong addr = get_ptr(cpu, maddr);

            if ((recursion_limit > 0) && (it != struct_hashtable.end()) && (addr != 0) && (sdef.name.compare(mdef.struct_name) != 0)) {
                if (pandalog) {
                    m->struct_type = strdup(mdef.struct_name.c_str());
                    m->struct_data = struct_logger(cpu, addr, it->second, pandalog, (recursion_limit - 1));
                } else {
                    struct_logger(cpu, addr, it->second, pandalog, (recursion_limit - 1));
                }
            } else {
                error = "read failed, unknown embeddded struct (struct ptr)";
            }

        // Recursive - member is double pointer to struct
        } else if ((mdef.type == DataType::STRUCT) && (mdef.is_ptr == true) && (mdef.is_double_ptr == true)) {

            auto it = struct_hashtable.find(mdef.struct_name);
            target_ulong addr_1 = get_ptr(cpu, maddr);
            target_ulong addr_2 = 0;

            if (addr_1 != 0) {
                addr_2 = get_ptr(cpu, addr_1);
            }

            if ((recursion_limit > 0) && (it != struct_hashtable.end()) && (addr_2 != 0) && (sdef.name.compare(mdef.struct_name) != 0)) {
                if (pandalog) {
                    m->struct_type = strdup(mdef.struct_name.c_str());
                    m->struct_data = struct_logger(cpu, addr_2, it->second, pandalog, (recursion_limit - 1));
                } else {
                    struct_logger(cpu, addr_2, it->second, pandalog, (recursion_limit - 1));
                }
            } else {
                error = "read failed, unknown embeddded struct (double ptr)";
            }

        // Non-recursive - member is a non-struct data type
        } else {

            std::pair<bool, PrimitiveVariant> read_result = read_member(cpu, maddr, mdef);

            if (read_result.first) {
                auto data = read_result.second;
                // Note we pass M which will be null if pandalog = false
                set_data(m, mdef, data);
            } else {
                error = "read failed, unknown embeddded struct (non-recursive)";
            }
        }

        if (!error.empty()) {
            if (pandalog) {
                m->str = strdup(error.c_str());
            } else {
                std::cout << "{" << error << " for struct " << mdef.struct_name << "}";
            }
        }
    }

    if (pandalog) {
        sdata->n_members = mcount;
        return sdata;
    } else {
        std::cout << "}";
        return NULL;
    }
}

void log_argument(CPUState* cpu, const syscall_info_t *call, int i, Panda__NamedData *sa, const syscall_ctx_t *rp) {
    // Handle arguments for a syscall
    // if SA is non-null, we write the arguments into the pandalog NamedData object
    // if SA is NULL, write arguments to stdout

    // Here we analyze the syscalls2-provide information about each system call

    uint8_t buf[MAX_STRLEN];

    if (sa == NULL) {
        // printing arguments - always start with name
        std::cout << call->argn[i] << "=";
    }

    // Special case: if an arg is named 'buf' and is a pointer
    // and the next arg is a size_t, unsigned long, or
    // with a name that contains 'size', 'len', or 'count'
    // we read the length and then capture that many bytes of the buf

    bool know_buf_len = false;
    uint64_t buf_len = 0;

    if (strcasestr(call->argn[i], "buf") != NULL // arg named buf
        && i < call->nargs-1 // has a next arg
        && (strcasestr(call->argn[i+1], "size")  != NULL ||
            strcasestr(call->argn[i+1], "len")   != NULL ||
            strcasestr(call->argn[i+1], "count") != NULL
           ) // next arg name contains size, len, or count
        ) {
        know_buf_len = true;

        // Some syscalls will have a max size as an arg and we'll need to calculate the actual size as a special-case
        // e.g., sys_read which has the actual buffer size in the return value
        if (strcmp(call->name, "sys_read") == 0) {
          buf_len = get_syscall_retval(cpu);
        } else {
            switch (call->argt[i+1]) {
              // Assume it will always be unsigned
              case SYSCALL_ARG_U64:
                  buf_len = (uint64_t) *((target_ulong *) rp->args[i+1]);
                  break;

              case SYSCALL_ARG_U32:
                  buf_len = (uint64_t) *((uint32_t *) rp->args[i+1]);
                  break;

              case SYSCALL_ARG_U16:
                  buf_len = (uint64_t) *((uint16_t *) rp->args[i+1]);
                  break;

              default:
                  printf("Unknown buffer size type for field %s %d\n", call->argn[i+1],
                                                                       call->argt[i+1]);
            }
        }
    }

    // Buf is a fixed size - ensure we don't overflow it
    buf_len = std::min(buf_len, (uint64_t)MAX_STRLEN);


    switch (call->argt[i]) {

        case SYSCALL_ARG_STR_PTR:
        {
            target_ulong addr = *((target_ulong *)rp->args[i]);

            if (know_buf_len) {
              // It's a buffer of a fixed length
              if (buf_len == 0) {
                if (sa) {
                  sa->bytes_val.data = NULL;
                } else {
                  std::cout << "\"\"";
                }
              } else {
                get_n_buf(cpu, addr, buf, buf_len);

                if (sa) {
                  unsigned char* data = (unsigned char*)malloc(sizeof(unsigned char)*buf_len);
                  assert(data != NULL);
                  memcpy(data, buf, buf_len);
                  sa->bytes_val.data = data;
                } else {
                  printf("\"%.*s\"", (int)buf_len, buf);
                }
              }
              if (sa) {
                sa->bytes_val.len = buf_len;
                sa->has_bytes_val = true;
              }

            }else{
                assert(strcmp("sys_write", call->name) != 0);

                int len = get_string(cpu, addr, buf);
                if (len > 0) {
                    sa->str = strdup((const char *) buf);
                } else {
                    sa->str = strdup("n/a");
                }
            }
            break;
        }

        case SYSCALL_ARG_STRUCT_PTR:
        {
            target_ulong ptr_val = *((target_ulong *)rp->args[i]);
            auto it = struct_hashtable.find(call->argtn[i]);

            if (it != struct_hashtable.end()) {
                StructDef sdef = it->second;
                // Note pointer may be null - that's allowed for some syscalls with structs - handled in struct_logger

                if (sa) {
                    sa->struct_type = strdup(call->argtn[i]);
                    sa->struct_data = struct_logger(cpu, ptr_val, sdef, true, STRUCT_RECURSION_LIMIT); // NULL if ptr_val == 0
                }else{
                    struct_logger(cpu, ptr_val, sdef, false, STRUCT_RECURSION_LIMIT);
                }

            } else {

                if (log_verbose) {
                    std::cerr << "[WARNING] syscalls_logger: No definition found for struct "
                        << "\'" << call->argtn[i] << "\' argument "
                        << std::endl;
                }

                if (sa) {
                    sa->ptr = (uint64_t)ptr_val;
                    sa->has_ptr = true;
                }else{
                    std::cerr << "(struct pointer error)";
                }
            }

            break;
        }

        case SYSCALL_ARG_BUF_PTR:
            if (know_buf_len) {
              // It's a buffer of a fixed length
              if (buf_len == 0) {
                  if (sa) {
                    sa->bytes_val.data = NULL;
                  } else {
                    std::cout << "NULL";
                  }
              } else {
                  get_n_buf(cpu, (target_ulong)*(target_ulong*) rp->args[i], buf, buf_len);

                  if (sa) {
                    unsigned char* data = (unsigned char*)malloc(sizeof(unsigned char)*buf_len);
                    assert(data != NULL);
                    memcpy(data, buf, buf_len);
                    sa->bytes_val.data = data;
                  } else {
                    printf("\"%.*s\"", (int)buf_len, buf);
                  }
              }
              if (sa) {
                sa->bytes_val.len = buf_len;
                sa->has_bytes_val = true;
              }

            } else { // Unknown length
              assert(strcmp("sys_write", call->name) != 0); // Sanity check - should always be known
              if (sa) {
                sa->ptr = (uint64_t) *((target_ulong *) rp->args[i]);
                sa->has_ptr = true;
              } else {
                // Unknown length, do our best to print something useful
                target_ulong addr = *((target_ulong *)rp->args[i]);
                int strlen = is_likely_string(cpu, addr);
                if (strlen == 0) {
                    std::cout << "NULL";
                }else if (strlen > 0) {
                    uint8_t buf[MAX_STRLEN];
                     get_string(cpu, addr, buf);
                    std::cout << "\"" << (const char*)buf << "\"";
                } else {
                    std::cout << "0x" << std::hex << (*((target_ulong *) rp->args[i]));
                }
              }
            }
            break;

        // TODO: the following cases are all nearly the same except the type and file names- would be good to macroize them
        case SYSCALL_ARG_U64:
            if (sa) {
                sa->u64 = (uint64_t) *((target_ulong *) rp->args[i]);
                sa->has_u64 = true;
            } else {
                if (*((uint64_t *) rp->args[i]) > 10) {
                  std::cout << std::hex << "0x";
                }else{
                  std::cout << std::dec;
                }
                std::cout << (*((uint64_t *) rp->args[i]));
            }
            break;

        case SYSCALL_ARG_U32:
            if (sa) {
                sa->u32 = *((uint32_t *) rp->args[i]);
                sa->has_u32 = true;
            }else {
                if (*((uint32_t *) rp->args[i]) > 10) {
                  std::cout << std::hex << "0x";
                }else{
                  std::cout << std::dec;
                }
                std::cout << (*((uint32_t *) rp->args[i]));
            }
            break;

        case SYSCALL_ARG_U16:
            if (sa) {
                sa->u16 = (uint32_t) *((uint16_t *) rp->args[i]);
                sa->has_u16 = true;
            } else {
                if (*((uint16_t *) rp->args[i]) > 10) {
                  std::cout << std::hex << "0x";
                }else{
                  std::cout << std::dec;
                }
                std::cout << (*((uint16_t *) rp->args[i]));
            }
            break;

        case SYSCALL_ARG_S64:
            if (sa) {
                sa->i64 = *((int64_t *) rp->args[i]);
                sa->has_i64 = true;
            } else {
                if (*((int64_t *) rp->args[i]) > 10) {
                  std::cout << std::hex << "0x";
                }else{
                  std::cout << std::dec;
                }
                std::cout << (*((int64_t *) rp->args[i]));
            }
            break;

        case SYSCALL_ARG_S32:
            if (sa) {
                sa->i32 = *((int32_t *) rp->args[i]);
                sa->has_i32 = true;
            } else {
                if (*((int32_t *) rp->args[i]) > 10) {
                  std::cout << std::hex << "0x";
                }else{
                  std::cout << std::dec;
                }
                std::cout << (*((int32_t *) rp->args[i]));
            }
            break;

        case SYSCALL_ARG_S16:
            if (sa) {
                sa->i16 = (int32_t) *((int16_t *) rp->args[i]);
                sa->has_i16 = true;
            } else {
                if (*((int16_t *) rp->args[i]) > 10) {
                  std::cout << std::hex << "0x";
                }else{
                  std::cout << std::dec;
                }
                std::cout << (*((int16_t *) rp->args[i]));
            }
            break;

        default:
            assert(false && "[ERROR] syscalls_logger: Unknown argument type!");
            break;
    }
}

void handle_syscall(CPUState *cpu, target_ulong pc, const syscall_info_t *call, const syscall_ctx_t *rp, bool is_return) {

    OsiProc *current = NULL;
    OsiThread *othread = NULL;

    // need to have current proc / thread
    current = get_current_process(cpu);
    if (current == NULL || current->pid == 0)
        return;

    othread = get_current_thread(cpu);
    if (othread == NULL)
        return;

    if (!call) {
        // This warning happens _a lot_ so I'm disabling it after the first
        if (!did_call_warning) {
          std::cerr << "[WARNING] syscalls_logger: null syscall_into_t*, missed a syscall! Disabling subsequent warnings" << std::endl;
          did_call_warning = true;
        }
        return;
    }

    if (target_process != NULL && strcmp(current->name, target_process) != 0) {
        // Target specified and it's not this one - bail
        return;
    }

    // Note that: pandalog mode supports capturing additional information for bind and execve which is not reported for
    // non-pandalog output.
    if (pandalog) {
        bool is_bind = strcmp(call->name, "sys_bind") == 0;
        bool is_execve = (strcmp(call->name, "sys_execve") == 0);
        bool has_fd = false;
        int fd_arg_position = -1;
        uint16_t sin_family = 0;

        // Examine arguments to determine if any is named 'fd' - if so we'll use OSI to get the filename for that FD
        for (int i = 0; i < call->nargs; i++) {
            //printf("arg name: %s\n", call->argn[i]);
            if (strcmp(call->argn[i], "fd") == 0) {
                has_fd = true;
                fd_arg_position = i; // Assume we'll only ever have one arg named 'fd' (which isn't true for for dup2)
                break;
            }
         }

        Panda__Syscall psyscall;
        psyscall = PANDA__SYSCALL__INIT;
        psyscall.pid = current->pid;
        psyscall.ppid = current->ppid;
        psyscall.tid = othread->tid;

        if (is_return) {
            psyscall.retcode = get_syscall_retval(cpu);
        } else {
            // We need to store a returncode (for the protobuf spec), but we don't have one for the syscalls where we record on enter.
            // For those we record 0. If a failure occurs, we'll run again on return and record the actual failing retcode then.
            psyscall.retcode = 0;
        }
        psyscall.create_time = current->create_time;
        psyscall.call_name = strdup(call->name);

        // If it's a bind, we only special case it if it's AF_INET/AF_INET6
        target_ulong address_of_addr_in = 0;

        if (is_bind) {
            address_of_addr_in = *((target_ulong *)rp->args[1]);
            uint8_t data[2] = {0};
            panda_virtual_memory_read(cpu, address_of_addr_in, data, 2);
            sin_family = *((uint16_t*) &data[0]);
            is_bind = sin_family == 2 || sin_family == 10;  // AF_INET or AF_INET6
        }

        // If we have any extra args, ensure we allocate enough space including those
        int nargs_to_store = call->nargs;

        // Special cases with extra args
        if (is_bind)   nargs_to_store++;
        if (is_execve) nargs_to_store++;
        if (has_fd)    nargs_to_store++;

        psyscall.args = (Panda__NamedData **)malloc(sizeof(Panda__NamedData *) * nargs_to_store);
        assert(psyscall.args != NULL);

        // Non-special case: regular arguments
        for (int i = 0; i < call->nargs; i++) {
            Panda__NamedData *sa = (Panda__NamedData *)malloc(sizeof(Panda__NamedData));
            assert(sa != NULL);
            psyscall.args[i] = sa;
            *sa = PANDA__NAMED_DATA__INIT;
            sa->arg_name = strdup(call->argn[i]);
            log_argument(cpu, call, i, sa, rp);
        }

        // Special case: extra args we want to store for bind/execve/FDs
        // Loop runs for the right # of times we need to add more, update flags within loop as we store things
        for (int i = call->nargs; i < nargs_to_store; i++) {

            if (is_bind) {
                // Read virtual memory to identify the port being bound to, add port as an extra argument (TODO: maybe we also want the address?)

                is_bind = false;
                uint8_t data[2] = {0};
                Panda__NamedData *sa = (Panda__NamedData *)malloc(sizeof(Panda__NamedData));
                assert(sa != NULL);
                psyscall.args[i] = sa;
                *sa = PANDA__NAMED_DATA__INIT;
                sa->arg_name = strdup("port");

                //sa->u16 = (uint32_t) *((uint16_t *) rp->args[i]);
                panda_virtual_memory_read(cpu, address_of_addr_in + 2, data, 2);
                uint16_t port = *((uint16_t*) &data[0]);
                port = ntohs(port);
                sa->u16 = port;
                sa->has_u16 = port;
            } else if(has_fd) {
                // use OSI_linux to resolve the  fd to a filename, add filename as an extra argument
                Panda__NamedData *sa = (Panda__NamedData *)malloc(sizeof(Panda__NamedData));
                assert(sa != NULL);
                psyscall.args[i] = sa;
                *sa = PANDA__NAMED_DATA__INIT;
                sa->arg_name = strdup("filename(from fd)");

                uint8_t fd_number = *(rp->args[fd_arg_position]);
                //printf("fd is: %d\n", fd_number);

                char* fn = NULL;
                fn = osi_linux_fd_to_filename(cpu, current, fd_number);

                unsigned char* filename_data = NULL;
                if (fn) {
                    //printf("filename: %s\n", fn);

                    uint64_t len = strlen(fn);
                    //printf("strlen %lu\n", len);
                    filename_data = (unsigned char*) malloc(sizeof(unsigned char) * len);
                    assert(filename_data != NULL);
                    memcpy(filename_data, fn, len);

                    //printf("filename: %s\n", filename_data);

                    sa->bytes_val.data = filename_data;
                    sa->bytes_val.len = len;
                    //sa->str = strdup("NAME");
                    sa->has_bytes_val = true;
                } else {
                    //printf("ifilename is null\n");

                    filename_data = (unsigned char*) malloc(sizeof(unsigned char) * 20);
                    sa->bytes_val.data = (unsigned char*) strdup("[unknown filename]");
                    sa->bytes_val.len = strlen("[unknown filename]");
                    sa->has_bytes_val = true;
                }
            } else if (is_execve) {
                // Read out the arg list and add as a new argument (TODO: maybe we also want the env list?)
                // execve("foo", ["foo", "zoo"]
                // argv = 0x100
                // 0x100: 0x200 => "foo
                // 0x108: 0x300 => "zoo"
                // 0x10c: 0
                target_ulong argv_ptr = 0;

                // Pass 1 - determine buffer size, include space for a space after each arg
                size_t buf_sz = 0;

                for (target_ulong argv = *((target_ulong *)rp->args[1]); argv != NULL; argv += sizeof(target_ulong)) {
                  // Read the address of the string into argv_ptr
                  panda_virtual_memory_read(cpu, argv, (uint8_t*)&argv_ptr, sizeof(target_ulong));
                  // arg_ptr is the address of the string, now read it!
                  if (!argv_ptr) break;

                  char buf[MAX_STRLEN];
                  get_string(cpu, argv_ptr, (uint8_t*) &buf);
                  buf_sz += strlen(buf)+1;
                }


                // Pass 2 - actually put them in the plog
                char * buffer = (char*)malloc(sizeof(char)*buf_sz);
                assert(buffer != NULL);
                buffer[0] = 0;

                for (target_ulong argv = *((target_ulong *)rp->args[1]); argv != NULL; argv += sizeof(target_ulong)) {
                  // Read the address of the string into argv_ptr
                  panda_virtual_memory_read(cpu, argv, (uint8_t*)&argv_ptr, sizeof(target_ulong));
                  // arg_ptr is the address of the string, now read it!
                  if (!argv_ptr) break;

                  char this_arg[MAX_STRLEN] = {0};
                  int rv = get_string(cpu, argv_ptr, (uint8_t*) &this_arg);

                  if (rv) {
                    strncat(buffer, this_arg, buf_sz-strlen(buffer));
                    strncat(buffer, " ", buf_sz-strlen(buffer)-1);
                  }
                }

                Panda__NamedData *sa = (Panda__NamedData *)malloc(sizeof(Panda__NamedData));
                assert(sa != NULL);
                psyscall.args[i] = sa;
                *sa = PANDA__NAMED_DATA__INIT;
                sa->arg_name = strdup("args");
                sa->str = strdup(buffer);
                //sa->has_str = true;

                //printf("EXECVE: %s\n", buffer);
                free(buffer);

            }else{
              assert(0 &&  "This should be unreachable");
            }
        }

        psyscall.n_args = nargs_to_store;
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        ple.syscall = &psyscall;
        ple.has_asid = true;
        ple.asid = current->asid;
        pandalog_write_entry(&ple);

        for (auto ptr : tmp_single_ptrs) {
            free(ptr);
        }
        tmp_single_ptrs.clear();

        for (auto ptr : tmp_double_ptrs) {
            free(ptr);
        }
        tmp_double_ptrs.clear();

        for (int i = 0; i < call->nargs; i++) {
            free(psyscall.args[i]);
        }
        free(psyscall.args);

    } else {

        if (target_process == NULL) {
            // Only log process details if we're logging multiple processes
            std::cout << "proc [pid=" << current->pid << ",ppid=" << current->ppid
                 << ",tid=" << othread->tid << ",create_time=" << current->create_time
                 << ",name=" << current->name << "]" << std::endl;
        }else{
            // if tracing one target with multiple pids, log on changes
            if (current->pid != last_pid) {
                if (last_pid != 0) {
                    // Skip initial log, like strace
                    std::cout << "[pid = " << std::dec << current->pid << "]" << std::endl;
                }
                last_pid = current->pid;
            }
        }

        target_long retval = get_syscall_retval(cpu);

        // Print name (skip past sys_ prefix)
        std::cout << call->name+4 << "(";

        for (int i = 0; i < call->nargs; i++) {
            if (i > 0) {
                std::cout << ", ";
            }
            log_argument(cpu, call, i, NULL, rp);
        }

        std::cout << ") =>";
        if (retval > 10) {
          std::cout << std::hex << "0x";
        }else{
          std::cout << std::dec;
        }
        std::cout << retval << std::endl;
    }
}

// Log arguments for every system call
void sys_return(CPUState *cpu, target_ulong pc, const syscall_info_t *call, const syscall_ctx_t *rp) {
  handle_syscall(cpu, pc, call, rp, true);
}

void sys_enter(CPUState *cpu, target_ulong pc, const syscall_info_t *call, const syscall_ctx_t *rp) {
    if (!call) {
        // This warning happens _a lot_ so I'm disabling it after the first
        if (!did_call_warning) {
          std::cerr << "[WARNING] syscalls_logger: null syscall_into_t*, missed a syscall! Disabling subsequent warnings" << std::endl;
          did_call_warning = true;
        }
        return;
    }
    // NOTE: if these syscalls fail, we'll initially record them (on enter) with a retval of 0
    // but we'll then also record them again (on return) with the actual retval.
    // In the non failure case, they never return and are only captured once.
    if(strcmp(call->name, "sys_exit") == 0 || strcmp(call->name, "sys_exit_group") == 0 ||
        strcmp(call->name, "sys_execve") == 0 || strcmp(call->name, "sys_execveat") == 0) {
    handle_syscall(cpu, pc, call, rp, false);
  }
}


bool init_plugin(void *_self) {

    panda_arg_list *args = panda_get_args("syscalls_logger");
    log_verbose = panda_parse_bool(args, "verbose");
    const char* json_filename = panda_parse_string_opt(args, "json", nullptr, "dwarf2json_output.json");
    target_process = panda_parse_string_opt(args, "target", nullptr, "Name of a single process to target. If unset, syscalls from all proceses are logged");
    did_call_warning=false;

    if (log_verbose) {
        std::cout << "[INFO] syscalls_logger: verbose output enabled." << std::endl;
    }

    if (!json_filename) {
        std::cerr << "[WARNING] syscalls_logger: No DWARF JSON provided, data logged will be incomplete." << std::endl;
    } else {
        std::ifstream ifs(json_filename);
        Json::Reader reader;
        Json::Value obj;

        if (!reader.parse(ifs, obj)) {
            std::cerr << "[ERROR] syscalls_logger: invalid DWARF JSON!" << std::endl;
            return false;
        } else {
            load_json(obj);
        }
    }

    // this is required in order to use the on_all_sys_[enter|return]2 cbs
    panda_add_arg("syscalls2", "load-info=1");
    panda_require("syscalls2");
    assert(init_syscalls2_api());

    panda_require("osi");
    assert(init_osi_api());
    assert(init_osi_linux_api());

    PPP_REG_CB("syscalls2", on_all_sys_enter2, sys_enter);
    PPP_REG_CB("syscalls2", on_all_sys_return2, sys_return);

    switch (panda_os_familyno) {

        case OS_LINUX: {
           return true;
        } break;

        default: {
            std::cerr << "[WARNING] syscalls_logger: This has never been tested for a non-Linux OS!" << std::endl;
            return true;
        }
    }
}

void uninit_plugin(void *_self) {
    // intentionally left blank
}
