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

void get_n_buf(CPUState *cpu, target_ulong addr, uint8_t *buf, uint64_t size) {
    // Populate buf with data at addr of the provided size

    int len = 0;
    uint8_t *c = (uint8_t*)&buf;
    // Read buffer, one character at a time (slower than a big read, but can handle failures?)
    while ((uint64_t)(len+&buf) < size) {
        int rv = panda_virtual_memory_read(cpu, addr + len, c, 1);
        if (rv == -1) {
            buf[len] = '.'; // Might also want to warn that data is unavailable
        }else if (!isprint(buf[len])) {
            buf[len] = '.'; // Only printable characters
        }
        len++;
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
Panda__StructData* array_logger(ReadableDataType& rdt, PrimitiveVariant& data) {

    uint8_t* buf = std::get<uint8_t*>(data);
    int arr_size = rdt.get_arr_size();

    if (arr_size <= 0) {
        return 0;
    }

    Panda__StructData *sdata = (Panda__StructData*)malloc(sizeof(Panda__StructData));
    assert(sdata != NULL);
    tmp_single_ptrs.push_back(sdata);
    *sdata = PANDA__STRUCT_DATA__INIT;

    Panda__NamedData** members = (Panda__NamedData **)malloc(sizeof(Panda__NamedData *) * arr_size);
    assert(members != NULL);
    tmp_double_ptrs.push_back(members);
    sdata->members = members;

    for (int i = 0; i < arr_size; i++) {

        uint8_t* data_ptr = buf + (i * rdt.arr_member_size_bytes);

        Panda__NamedData *m = (Panda__NamedData *)malloc(sizeof(Panda__NamedData));
        assert(m != NULL);
        tmp_single_ptrs.push_back(m);

        sdata->members[i] = m;
        *m = PANDA__NAMED_DATA__INIT;

        switch (rdt.arr_member_type) {
            case DataType::BOOL:
            case DataType::INT:
                if (rdt.is_signed) {
                    switch (rdt.size_bytes) {
                        case sizeof(short int):
                            m->i16 = *(short int*)data_ptr;
                            m->has_i16 = true;
                            break;
                        case sizeof(int):
                            m->i32 = *(int*)data_ptr;
                            m->has_i32 = true;
                            break;
                        case sizeof(long int):
                            m->i64 = *(long int*)data_ptr;
                            m->has_i64 = true;
                            break;
                        default:
                            return 0;
                            break;
                    }
                } else {
                    switch (rdt.size_bytes) {
                        case sizeof(short unsigned):
                            m->u16 = *(short unsigned*)data_ptr;
                            m->has_u16 = true;
                            break;
                        case sizeof(unsigned):
                            m->u32 = *(unsigned*)data_ptr;
                            m->has_u32 = true;
                            break;
                        case sizeof(long unsigned):
                            m->u64 = *(long unsigned*)data_ptr;
                            m->has_u64 = true;
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
                        m->float_val = *(float*)data_ptr;
                        m->has_float_val = true;
                        break;
                    case sizeof(double):
                        m->double_val = *(float*)data_ptr;
                        m->has_double_val = true;
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

    sdata->n_members = arr_size;
    return sdata;
}

// Helper for struct_logger
void set_data(Panda__NamedData* nd, ReadableDataType& rdt, PrimitiveVariant& data) {
    switch (data.index()) {
        case VariantType::VT_BOOL:
            nd->bool_val = std::get<bool>(data);
            nd->has_bool_val = true;
            break;
        case VariantType::VT_CHAR:
            {
                static_assert(sizeof(char) == 1);
                std::string char_str(1, std::get<char>(data));
                nd->str = strdup(char_str.c_str());
            }
            break;
        case VariantType::VT_SHORT_INT:
            static_assert(sizeof(short int) == 2);
            nd->i16 = std::get<short int>(data);
            nd->has_i16 = true;
            break;
        case VariantType::VT_INT:
            static_assert(sizeof(int) == 4);
            nd->i32 = std::get<int>(data);
            nd->has_i32 = true;
            break;
        case VariantType::VT_LONG_INT:
            static_assert(sizeof(long int) == 8);
            nd->i64 = std::get<long int>(data);
            nd->has_i64 = true;
            break;
        case VariantType::VT_SHORT_UNSIGNED:
            static_assert(sizeof(short unsigned) == 2);
            nd->u16 = std::get<short unsigned>(data);
            nd->has_u16 = true;
            break;
        case VariantType::VT_UNSIGNED:
            static_assert(sizeof(unsigned) == 4);
            nd->u32 = std::get<unsigned>(data);
            nd->has_u32 = true;
            break;
        case VariantType::VT_LONG_UNSIGNED:
            static_assert(sizeof(long unsigned) == 8);
            nd->u64 = std::get<long unsigned>(data);
            nd->has_u64 = true;
            break;
        case VariantType::VT_FLOAT:
            nd->float_val = std::get<float>(data);
            nd->has_float_val = true;
            break;
        case VariantType::VT_DOUBLE:
            nd->double_val = std::get<double>(data);
            nd->has_double_val = true;
            break;
        case VariantType::VT_LONG_DOUBLE:
            nd->double_val = (double)std::get<long double>(data);
            nd->has_double_val = true;
            std::cerr << "[WARNING] syscalls_logger: casting long double to double (only latter supported by protobuf)" << std::endl;
            break;
        case VariantType::VT_UINT8_T_PTR:
        {
            char* str_ptr = (char *)std::get<uint8_t*>(data);
            if ((rdt.type == DataType::ARRAY) && (rdt.arr_member_type == DataType::CHAR) && check_str(str_ptr)) {
                nd->str = strdup(str_ptr);
                return;
            } else if ((rdt.type == DataType::ARRAY) && (rdt.arr_member_type != DataType::CHAR)) {
                auto sdata = array_logger(rdt, data);
                if (sdata) {
                    nd->struct_type = strdup("ArrayOfPrimitive");
                    nd->struct_data = sdata;
                    return;
                }
            }

            assert(rdt.type != DataType::STRUCT);
            // TODO: how to convert to protobuf bytes? This is a host pointer, not helpful
            nd->ptr = (uint64_t)std::get<uint8_t*>(data);
            nd->has_ptr = true;
            break;
        }
        default:
            assert(false && "FATAL: default case should never hit, function \"set_data()\"");
            break;
    }
}

// TODO: reduce code repetition in recursive cases
// Recursively read struct information for PANDALOG, using DWARF layout information
Panda__StructData* struct_logger(CPUState *cpu, target_ulong saddr, StructDef& sdef, int recursion_limit) {

    int mcount = sdef.members.size();
    bool null_ptr_err = (saddr == 0);

    Panda__StructData *sdata = (Panda__StructData*)malloc(sizeof(Panda__StructData));
    assert(sdata != NULL);
    tmp_single_ptrs.push_back(sdata);
    *sdata = PANDA__STRUCT_DATA__INIT;

    Panda__NamedData** members = (Panda__NamedData **)malloc(sizeof(Panda__NamedData *) * mcount);
    assert(members != NULL);
    tmp_double_ptrs.push_back(members);
    sdata->members = members;

    for (int i = 0; i < mcount; i++) {

        ReadableDataType mdef = sdef.members[i];
        target_ulong maddr = saddr + mdef.offset_bytes;
        Panda__NamedData *m = (Panda__NamedData *)malloc(sizeof(Panda__NamedData));
        assert(m != NULL);
        tmp_single_ptrs.push_back(m);

        sdata->members[i] = m;
        *m = PANDA__NAMED_DATA__INIT;
        m->arg_name = strdup(mdef.name.c_str());

        if (log_verbose) {
            std::cout << "[INFO] syscalls_logger: loading struct " << sdef.name
                << ", member: " << mdef.name
                << ", addr: 0x" << std::hex << maddr << std::dec << std::endl;
        }

        // Recursive - member is embedded struct
        if ((mdef.type == DataType::STRUCT) && (mdef.is_ptr == false)) {

            auto it = struct_hashtable.find(mdef.struct_name);

            if ((recursion_limit > 0) && it != struct_hashtable.end() && (sdef.name.compare(mdef.struct_name) != 0)) {
                m->struct_type = strdup(mdef.struct_name.c_str());
                m->struct_data = struct_logger(cpu, maddr, it->second, (recursion_limit - 1));
            } else {
                if (null_ptr_err) {
                    m->str = strdup("{read failed, SC2 returned a NULL pointer (bug)}");
                } else {
                    m->str = strdup("{read failed, unknown embedded struct}");
                }
            }

        // Recursive - member is pointer to struct
        } else if ((mdef.type == DataType::STRUCT) && (mdef.is_ptr == true) && (mdef.is_double_ptr == false)) {

            auto it = struct_hashtable.find(mdef.struct_name);
            target_ulong addr = get_ptr(cpu, maddr);

            if ((recursion_limit > 0) && (it != struct_hashtable.end()) && (addr != 0) && (sdef.name.compare(mdef.struct_name) != 0)) {
                m->struct_type = strdup(mdef.struct_name.c_str());
                m->struct_data = struct_logger(cpu, addr, it->second, (recursion_limit - 1));
            } else {
                if (null_ptr_err) {
                    m->str = strdup("{read failed, SC2 returned a NULL pointer (bug)}");
                } else {
                    m->str = strdup("{read failed, unknown struct ptr}");
                }
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
                m->struct_type = strdup(mdef.struct_name.c_str());
                m->struct_data = struct_logger(cpu, addr_2, it->second, (recursion_limit - 1));
            } else {
                if (null_ptr_err) {
                    m->str = strdup("{read failed, SC2 returned a NULL pointer (bug)}");
                } else {
                    m->str = strdup("{read failed, unknown struct double ptr}");
                }
            }

        // Non-recursive - member is a non-struct data type
        } else {

            std::pair<bool, PrimitiveVariant> read_result = read_member(cpu, maddr, mdef);

            if (read_result.first) {
                auto data = read_result.second;
                set_data(m, mdef, data);
            } else {
                if (null_ptr_err) {
                    m->str = strdup("{read failed, SC2 returned a NULL pointer (bug)}");
                } else {
                    m->str = strdup("{read failed, unknown data}");
                }
            }
        }
    }

    sdata->n_members = mcount;
    return sdata;
}


// Log arguments for every system call
void sys_return(CPUState *cpu, target_ulong pc, const syscall_info_t *call, const syscall_ctx_t *rp) {

    OsiProc *current = NULL;
    OsiThread *othread = NULL;
    uint8_t buf[MAX_STRLEN];

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

    if (pandalog) {
        bool is_bind = false;
        uint16_t sin_family = 0;
        if(strcmp(call->name, "sys_bind") == 0) {
            is_bind = true;
        }


        Panda__Syscall psyscall;
        psyscall = PANDA__SYSCALL__INIT;
        psyscall.pid = current->pid;
        psyscall.ppid = current->ppid;
        psyscall.tid = othread->tid;
        psyscall.retcode = get_syscall_retval(cpu);
        psyscall.create_time = current->create_time;
        psyscall.call_name = strdup(call->name);
        if(is_bind) {
            psyscall.args = (Panda__NamedData **)malloc(sizeof(Panda__NamedData *) * call->nargs+1);
        } else {
            psyscall.args = (Panda__NamedData **)malloc(sizeof(Panda__NamedData *) * call->nargs);
        }
        assert(psyscall.args != NULL);

        for (int i = 0; i < ((is_bind) ? (call->nargs+1) : (call->nargs)); i++) { //I am so sorry for making you look at this
            if(is_bind && i == 3) {
                uint8_t data[2] = {0};
                //printf("sys_bind happened, at extra arg cycle!\n");

                //get the value of the pointer (second arg of bind)
                target_ulong address_of_addr_in = 0;
                address_of_addr_in = *((target_ulong *)rp->args[1]);
                //printf("address of struct in_addr: " TARGET_PTR_FMT "\n", address_of_addr_in);

                //get the sin_family value
                panda_virtual_memory_read(cpu, address_of_addr_in, data, 2);
                sin_family = *((uint16_t*) &data[0]);
                //printf("sin_family value: %d\n", sin_family);

                if(sin_family == 2 || sin_family == 10) { //AF_INET or AF_INET6

                    Panda__NamedData *sa = (Panda__NamedData *)malloc(sizeof(Panda__NamedData));
                    assert(sa != NULL);
                    psyscall.args[i] = sa;
                    *sa = PANDA__NAMED_DATA__INIT;
                    sa->arg_name = strdup("port");

                    //sa->u16 = (uint32_t) *((uint16_t *) rp->args[i]);




                    panda_virtual_memory_read(cpu, address_of_addr_in + 2, data, 2);
                    uint16_t port = *((uint16_t*) &data[0]);
                    port = ntohs(port);

                    //printf("inet socket!! port is: %d\n", port);
                    sa->u16 = port;

                    sa->has_u16 = true;
                } else {
                    //printf("not an inet socket\n");
                }


                break;
            }

            //if(is_bind && (sin_family == 2 || sin_family == 10)) {}


            Panda__NamedData *sa = (Panda__NamedData *)malloc(sizeof(Panda__NamedData));
            assert(sa != NULL);
            psyscall.args[i] = sa;
            *sa = PANDA__NAMED_DATA__INIT;
            sa->arg_name = strdup(call->argn[i]);

            // Special case: if an arg is named 'buf' and is a pointer
            // and the next arg is a size_t, unsigned long, or
            // with a name that contains 'size', 'len', or 'count'
            // we read the length and then capture that many bytes of the buf

            bool know_buf_len = false;
            uint64_t buf_len = 0;

            if (strcasestr(sa->arg_name, "buf") != NULL // arg named buf
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
                  buf_len = psyscall.retcode;
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
                        sa->bytes_val.data = NULL;
                      } else {
                        get_n_buf(cpu, addr, buf, buf_len);
                        unsigned char* data = (unsigned char*)malloc(sizeof(unsigned char)*buf_len);
                        assert(data != NULL);
                        memcpy(data, buf, buf_len);

                        //printf("Set arg str_ptr for %s to %s\n", call->name, data);
                        sa->bytes_val.data = data;
                      }
                      sa->bytes_val.len = buf_len;
                      sa->has_bytes_val = true;

                    }else{
                        assert(strcmp("sys_write", call->name) != 0);

                        int len = get_string(cpu, addr, buf);
                        if (len > 0) {
                            sa->str = strdup((const char *) buf);
                        }
                        else {
                            sa->str = strdup("n/a");
                        }
                    }
                    //sa->has_str = true;
                    break;
                }

                case SYSCALL_ARG_STRUCT_PTR:
                {
                    target_ulong ptr_val = *((target_ulong *)rp->args[i]);
                    auto it = struct_hashtable.find(call->argtn[i]);

                    if (it != struct_hashtable.end()) {

                        StructDef sdef = it->second;

                        if (!ptr_val) {
                            std::cerr << "[WARNING] syscalls_logger: SC2 returned NULL pointer for "
                                << "\'" << call->name << "\' argument "
                                << "\'" <<  call->argn[i] << "\'"
                                << "(type: \'" <<  call->argtn[i] << "\')"
                                << std::endl;
                        }

                        sa->struct_type = strdup(call->argtn[i]);
                        sa->struct_data = struct_logger(cpu, ptr_val, sdef, STRUCT_RECURSION_LIMIT);
                    } else {

                        if (log_verbose) {
                            std::cerr << "[WARNING] syscalls_logger: No definition found for struct "
                                << "\'" << call->argtn[i] << "\' argument "
                                << std::endl;
                        }

                        assert(strcmp("sys_write", call->name) != 0);
                        sa->ptr = (uint64_t)ptr_val;
                        sa->has_ptr = true;
                    }

                    break;
                }

                case SYSCALL_ARG_BUF_PTR:
                    if (know_buf_len) {
                      // It's a buffer of a fixed length
                      if (buf_len == 0) {
                          sa->bytes_val.data = NULL;
                      } else {
                          get_n_buf(cpu, (target_ulong)*(target_ulong*) rp->args[i], buf, buf_len);
                          unsigned char* data = (unsigned char*)malloc(sizeof(unsigned char)*buf_len);
                          assert(data != NULL);
                          memcpy(data, buf, buf_len);
                          //printf("Set arg buf_ptr for %s to %s\n", call->name, data);

                          sa->bytes_val.data = data;
                      }
                      sa->bytes_val.len = buf_len;
                      sa->has_bytes_val = true;

                    } else {
                      assert(strcmp("sys_write", call->name) != 0);
                      sa->ptr = (uint64_t) *((target_ulong *) rp->args[i]);
                      sa->has_ptr = true;
                    }
                    break;

                case SYSCALL_ARG_U64:
                    sa->u64 = (uint64_t) *((target_ulong *) rp->args[i]);
                    sa->has_u64 = true;
                    break;

                case SYSCALL_ARG_U32:
                    sa->u32 = *((uint32_t *) rp->args[i]);
                    sa->has_u32 = true;
                    break;

                case SYSCALL_ARG_U16:
                    sa->u16 = (uint32_t) *((uint16_t *) rp->args[i]);
                    sa->has_u16 = true;
                    break;

                case SYSCALL_ARG_S64:
                    sa->i64 = *((int64_t *) rp->args[i]);
                    sa->has_i64 = true;
                    break;

                case SYSCALL_ARG_S32:
                    sa->i32 = *((int32_t *) rp->args[i]);
                    sa->has_i32 = true;
                    break;

                case SYSCALL_ARG_S16:
                    sa->i16 = (int32_t) *((int16_t *) rp->args[i]);
                    sa->has_i16 = true;
                    break;

                default:
                    assert(false && "[ERROR] syscalls_logger: Unknown argument type!");
                    break;
            }
        }

        if(is_bind && (sin_family == 2 || sin_family == 10)) { //add an extra argument iff it's a network socket
            psyscall.n_args = call->nargs + 1;
        } else {
            psyscall.n_args = call->nargs;
        }
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

        std::cout << "proc [pid=" << current->pid << ",ppid=" << current->ppid
             << ",tid=" << othread->tid << ",create_time=" << current->create_time
             << ",name=" << current->name << "]" << std::endl;

        std::cout << " syscall ret pc=" << std::hex << pc << " name=" << call->name << std::endl;

        for (int i = 0; i < call->nargs; i++) {

            std::cout << "  arg " << i << " - ";
            switch (call->argt[i]) {

                case SYSCALL_ARG_STR_PTR:
                {
                    target_ulong addr = *((target_ulong *)rp->args[i]);
                    int len = get_string(cpu, addr, buf);
                    std::cout << call->argn[i] << ": str[";
                    if (len > 0)
                        std::cout << buf;
                    std::cout << "]" << std::endl;
                    break;
                }
                case SYSCALL_ARG_BUF_PTR:
                    std::cout << call->argn[i] << ": buf ptr[" << std::hex << (*((target_ulong *) rp->args[i])) << "]" << std::endl;
                    break;

                case SYSCALL_ARG_STRUCT_PTR:
                    std::cout << call->argn[i] << ": struct ptr[" << std::hex << (*((target_ulong *) rp->args[i])) << "]" << std::endl;
                    break;

                case SYSCALL_ARG_U64:
                    std::cout << call->argn[i] << ": u64[" << (*((uint64_t *) rp->args[i])) << "]" << std::endl;
                    break;

                case SYSCALL_ARG_U32:
                    std::cout << call->argn[i] << ": u32[" << (*((uint32_t *) rp->args[i])) << "]" << std::endl;
                    break;

                case SYSCALL_ARG_U16:
                    std::cout << call->argn[i] << ": u16[" << (*((uint16_t *) rp->args[i])) << "]" << std::endl;
                    break;

                case SYSCALL_ARG_S64:
                    std::cout << call->argn[i] << ": i64[" << (*((int64_t *) rp->args[i])) << "]" << std::endl;
                    break;

                case SYSCALL_ARG_S32:
                    std::cout << call->argn[i] << ": i32[" << (*((int32_t *) rp->args[i])) << "]" << std::endl;
                    break;

                case SYSCALL_ARG_S16:
                    std::cout << call->argn[i] << ": i16[" << (*((int16_t *) rp->args[i])) << "]" << std::endl;
                    break;

                default:
                    break;

            }
        }
    }
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

    //only do stuff for syscalls we care about that don't return
    if(strcmp(call->name, "sys_exit") == 0 || strcmp(call->name, "sys_exit_group") == 0 ||
        strcmp(call->name, "sys_execve") == 0 || strcmp(call->name, "sys_execveat") == 0) {

        OsiProc *current = NULL;
        OsiThread *othread = NULL;
        uint8_t buf[MAX_STRLEN];

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


        if (pandalog) {
            Panda__Syscall psyscall;
            psyscall = PANDA__SYSCALL__INIT;
            psyscall.pid = current->pid;
            psyscall.ppid = current->ppid;
            psyscall.tid = othread->tid;

            //this is to make protobuf happy, not because sys_execve and sys_exit return 0
            psyscall.retcode = 0;

            psyscall.create_time = current->create_time;
            psyscall.call_name = strdup(call->name);
            psyscall.args = (Panda__NamedData **)malloc(sizeof(Panda__NamedData *) * call->nargs);
            assert(psyscall.args != NULL);

            for (int i = 0; i < call->nargs; i++) {

                

                Panda__NamedData *sa = (Panda__NamedData *)malloc(sizeof(Panda__NamedData));
                assert(sa != NULL);
                psyscall.args[i] = sa;
                *sa = PANDA__NAMED_DATA__INIT;
                sa->arg_name = strdup(call->argn[i]);
                switch (call->argt[i]) {

                    case SYSCALL_ARG_STR_PTR:
                    {
                        target_ulong addr = *((target_ulong *)rp->args[i]);
                        int len = get_string(cpu, addr, buf);
                        if (len > 0) {
                            sa->str = strdup((const char *) buf);
                        }
                        else {
                            sa->str = strdup("n/a");
                        }
                        //sa->has_str = true;
                        break;
                    }

                    case SYSCALL_ARG_STRUCT_PTR:
                    {
                        target_ulong ptr_val = *((target_ulong *)rp->args[i]);
                        auto it = struct_hashtable.find(call->argtn[i]);

                        if (it != struct_hashtable.end()) {

                            StructDef sdef = it->second;

                            if (!ptr_val) {
                                std::cerr << "[WARNING] syscalls_logger: SC2 returned NULL pointer for "
                                    << "\'" << call->name << "\' argument "
                                    << "\'" <<  call->argn[i] << "\'"
                                    << "(type: \'" <<  call->argtn[i] << "\')"
                                    << std::endl;
                            }

                            sa->struct_type = strdup(call->argtn[i]);
                            sa->struct_data = struct_logger(cpu, ptr_val, sdef, STRUCT_RECURSION_LIMIT);
                        } else {

                            if (log_verbose) {
                                std::cerr << "[WARNING] syscalls_logger: No definition found for struct "
                                    << "\'" << call->argtn[i] << "\' argument "
                                    << std::endl;
                            }

                            sa->ptr = (uint64_t)ptr_val;
                            assert(strcmp("sys_write", call->name) != 0);
                            sa->has_ptr = true;
                        }

                        break;
                    }

                    case SYSCALL_ARG_BUF_PTR:
                        assert(strcmp("sys_write", call->name) != 0);
                        sa->ptr = (uint64_t) *((target_ulong *) rp->args[i]);
                        sa->has_ptr = true;
                        break;

                    case SYSCALL_ARG_U64:
                        sa->u64 = (uint64_t) *((target_ulong *) rp->args[i]);
                        sa->has_u64 = true;
                        break;

                    case SYSCALL_ARG_U32:
                        sa->u32 = *((uint32_t *) rp->args[i]);
                        sa->has_u32 = true;
                        break;

                    case SYSCALL_ARG_U16:
                        sa->u16 = (uint32_t) *((uint16_t *) rp->args[i]);
                        sa->has_u16 = true;
                        break;

                    case SYSCALL_ARG_S64:
                        sa->i64 = *((int64_t *) rp->args[i]);
                        sa->has_i64 = true;
                        break;

                    case SYSCALL_ARG_S32:
                        sa->i32 = *((int32_t *) rp->args[i]);
                        sa->has_i32 = true;
                        break;

                    case SYSCALL_ARG_S16:
                        sa->i16 = (int32_t) *((int16_t *) rp->args[i]);
                        sa->has_i16 = true;
                        break;

                    default:
                        assert(false && "[ERROR] syscalls_logger: Unknown argument type!");
                        break;
                }
            }

            psyscall.n_args = call->nargs;
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
        }
    }
}


bool init_plugin(void *_self) {

    panda_arg_list *args = panda_get_args("syscalls_logger");
    log_verbose = panda_parse_bool(args, "verbose");
    const char* json_filename = panda_parse_string_opt(args, "json", nullptr, "dwarf2json_output.json");
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
