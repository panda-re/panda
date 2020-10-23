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

// Is this a reasonable max strlen for a syscall arg?
#define MAX_STRLEN 128

std::vector<void*> tmp_single_ptrs;
std::vector<void*> tmp_double_ptrs;

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

// Read a pointer from guest memory
target_ulong get_ptr(CPUState *cpu, target_ulong addr) {
    target_ulong ptr;
    if (panda_virtual_memory_read(cpu, addr, (uint8_t*)&ptr, sizeof(target_ulong)) != 0) {
        ptr = 0;
    }
    return ptr;
}

// TODO: finish implementation to cover all cases
// Helper for struct_logger
void set_data(Panda__NamedData* nd, ReadableDataType& rdt, PrimitiveVariant& data) {

    nd->arg_name = strdup(rdt.name.c_str());

    switch (data.index()) {
        case VariantType::VT_BOOL:
            nd->bool_val = std::get<bool>(data);
            nd->has_bool_val = true;
            std::cout << "[TEMP DEBUG MEMBER]: " << rdt.name << ": " << std::get<bool>(data) << std::endl;
            break;
        case VariantType::VT_CHAR:
            assert(false && "TODO: Unhandled PANDALOG case (char)! Needs implementing");
            break;
        case VariantType::VT_INT:
            nd->i64 = std::get<int>(data);
            nd->has_i64 = true;
            std::cout << "[TEMP DEBUG MEMBER]: " << rdt.name << ": " << std::get<int>(data) << std::endl;
            break;
        case VariantType::VT_LONG_INT:
            assert(sizeof(long int) == 8);
            nd->i64 = std::get<long int>(data);
            nd->has_i64 = true;
            std::cout << "[TEMP DEBUG MEMBER]: " << rdt.name << ": " << std::get<long int>(data) << std::endl;
            break;
        case VariantType::VT_UNSIGNED:
            nd->u64 = std::get<unsigned>(data);
            nd->has_u64 = true;
            std::cout << "[TEMP DEBUG MEMBER]: " << rdt.name << ": " << std::get<unsigned>(data) << std::endl;
            break;
        case VariantType::VT_LONG_UNSIGNED:
            assert(sizeof(long unsigned) == 8);
            nd->u64 = std::get<long unsigned>(data);
            nd->has_u64 = true;
            std::cout << "[TEMP DEBUG MEMBER]: " << rdt.name << ": " << std::get<long unsigned>(data) << std::endl;
            break;
        case VariantType::VT_FLOAT:
            nd->float_val = std::get<float>(data);
            nd->has_float_val = true;
            std::cout << "[TEMP DEBUG MEMBER]: " << rdt.name << ": " << std::get<float>(data) << std::endl;
            break;
        case VariantType::VT_DOUBLE:
            nd->double_val = std::get<double>(data);
            nd->has_double_val = true;
            std::cout << "[TEMP DEBUG MEMBER]: " << rdt.name << ": " << std::get<double>(data) << std::endl;
            break;
        case VariantType::VT_LONG_DOUBLE:
            assert(false && "TODO: Unhandled PANDALOG case (long double)! Needs implementing");
            break;
        case VariantType::VT_UINT8_T_PTR:
            if ((rdt.type == DataType::ARRAY) && (rdt.arr_member_type == DataType::CHAR)) {
                nd->str = strdup((const char *)std::get<uint8_t*>(data));
                printf("[TEMP DEBUG MEMBER] STR_MEMBER: %s: %s\n", rdt.name.c_str(), (const char *)std::get<uint8_t*>(data));
            } else {
                std::cerr << rdt << std::endl;
                assert(false && "TODO: Unhandled PANDALOG case (unit8_t*)! Needs implementing");
            }
            break;
        default:
            assert(false && "FATAL: default case should never hit, function \"set_data()\"");
            break;
    }
}

// Recursively read struct information for PANDALOG, using DWARF layout information
//Panda__StructData* struct_logger(CPUState *cpu, target_ulong saddr, StructDef& sdef) {
Panda__NamedData** struct_logger(CPUState *cpu, target_ulong saddr, StructDef& sdef) {

    /*
    Panda__StructData *sdata = (Panda__StructData*)malloc(sizeof(Panda__StructData));
    assert(sdata != NULL);
    tmp_single_ptrs.push_back(sdata);
    *sdata = PANDA__STRUCT_DATA__INIT;
    */

    Panda__NamedData** members = (Panda__NamedData **)malloc(sizeof(Panda__NamedData *) * sdef.members.size());
    assert(members != NULL);
    tmp_double_ptrs.push_back(members);
    //sdata->members = members;

    for (int i = 0; i < sdef.members.size(); i++) {

        ReadableDataType mdef = sdef.members[i];
        //target_ulong maddr = saddr + mdef.offset_bytes;
        Panda__NamedData *m = (Panda__NamedData *)malloc(sizeof(Panda__NamedData));
        assert(m != NULL);
        tmp_single_ptrs.push_back(m);

        members[i] = m;
        *m = PANDA__NAMED_DATA__INIT;
        m->arg_name = strdup("TEMP TEST");
        m->u64 = 1337;
        m->has_u64 = true;

        /*
        if (log_verbose) {
            std::cout << "[INFO] syscalls_logger: loading struct " << sdef.name
                << ", member: " << mdef.name
                << ", addr: 0x" << std::hex << maddr << std::dec << std::endl;
        }

        // Recursive - member is embedded struct
        if ((mdef.type == DataType::STRUCT) && (mdef.is_ptr == false)) {

            auto it = struct_hashtable.find(mdef.name);

            if (it != struct_hashtable.end()) {
                m->struct_data = struct_logger(cpu, maddr, it->second);
            } else {
                m->str = strdup("{read failed, unknown embedded struct}");
            }

        // Recursive - member is pointer to struct
        } else if ((mdef.type == DataType::STRUCT) && (mdef.is_ptr == true) && (mdef.is_double_ptr == false)) {

            auto it = struct_hashtable.find(mdef.name);
            target_ulong addr = get_ptr(cpu, maddr);

            if (it != struct_hashtable.end() && (addr != 0)) {
                m->struct_data = struct_logger(cpu, addr, it->second);
            } else {
                m->str = strdup("{read failed, unknown struct ptr}");
            }

        // Recursive - member is double pointer to struct
        } else if ((mdef.type == DataType::STRUCT) && (mdef.is_ptr == true) && (mdef.is_double_ptr == true)) {

            auto it = struct_hashtable.find(mdef.name);
            target_ulong addr_1 = get_ptr(cpu, maddr);
            target_ulong addr_2 = 0;

            if (addr_1 != 0) {
                addr_2 = get_ptr(cpu, addr_1);
            }

            if (it != struct_hashtable.end() && (addr_2 != 0)) {
                m->struct_data = struct_logger(cpu, addr_2, it->second);
            } else {
                m->str = strdup("{read failed, unknown struct double ptr}");
            }

        // Non-recursive - member is a non-struct data type
        } else {

            std::pair<bool, PrimitiveVariant> read_result = read_member(cpu, maddr, mdef);

            if (read_result.first) {
                auto data = read_result.second;
                set_data(m, mdef, data);
            } else {
                m->str = strdup("{read failed, unknown data}");
            }
        }
        */
    }

    //return sdata;
    return members;
}

// TODO: comment this
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
        std::cerr << "[WARNING] syscalls_logger: null syscall_into_t*, missed a syscall!" << std::endl;
        return;
    }

    if (pandalog) {

        Panda__Syscall psyscall;
        psyscall = PANDA__SYSCALL__INIT;
        psyscall.pid = current->pid;
        psyscall.ppid = current->ppid;
        psyscall.tid = othread->tid;
        psyscall.retcode = get_syscall_retval(cpu);
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
                        //sa->struct_data = struct_logger(cpu, ptr_val, sdef);
                        sa->struct_members = struct_logger(cpu, ptr_val, sdef);
                    } else {
                        sa->ptr = (uint64_t)ptr_val;
                        sa->has_ptr = true;
                    }

                    break;
                }

                case SYSCALL_ARG_BUF_PTR:
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

bool init_plugin(void *_self) {

    panda_arg_list *args = panda_get_args("syscalls_logger");
    log_verbose = panda_parse_bool(args, "verbose");
    const char* json_filename = panda_parse_string_opt(args, "json", nullptr, "dwarf2json_output.json");

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

    // PPP_REG_CB("syscalls2", on_all_sys_enter2, sys_enter);
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