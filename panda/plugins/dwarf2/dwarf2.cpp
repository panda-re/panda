/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Zhenghao Hu            huzh@nyu.edu
 *  Andrew Quijano         andrew.quijano@nyu.edu
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
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <string>
#include <algorithm>

#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <json/json.h>

extern "C" {

#include "panda/rr/rr_log.h"
#include "panda/plog.h"
#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "dwarf2_util.h"
#include "dwarf2.h"
#include "dwarf2_types.h"

#include "pri/pri_types.h"
#include "pri/pri_ext.h"
#include "pri/pri.h"

#include "osi/osi_types.h"
#include "osi/osi_ext.h"

// this provides the fd resolution magic
#include "osi_linux/osi_linux_ext.h"

#include "syscalls2/syscalls_ext_typedefs.h"

#include "loaded/loaded.h"

bool init_plugin(void *);
void uninit_plugin(void *);

void on_library_load(CPUState *cpu, target_ulong pc, char *lib_name, target_ulong base_addr, target_ulong size);
void on_all_livevar_iter(CPUState *cpu, target_ulong pc, liveVarCB f, void *args);

void on_funct_livevar_iter(CPUState *cpu, target_ulong pc, liveVarCB f, void *args);

void on_global_livevar_iter(CPUState *cpu, target_ulong pc, liveVarCB f, void *args);

#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

}

#define dprintf(...) if (debug) { printf(__VA_ARGS__); fflush(stdout); }

#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"

const char *guest_debug_path = NULL;
const char *host_debug_path = NULL;
const char *host_mount_path = NULL;
const char *proc_to_monitor = NULL;
bool allow_just_plt = false;
bool logCallSites = true;
std::string bin_path;

// For a better understanding, look at the JSON ending in "_func_info.json"
// You can search for terms such as "DW_OP_reg6", these maps help map the DWARF register
// to the right register in i386/ARM/X86-64/AARCH64 architectures
// Take a close look at the following PR for detailed analysis
// https://github.com/panda-re/panda/pull/1619
// See here for reference of how register map was obtained.
// https://github.com/panda-re/panda/blob/dev/panda/python/core/pandare/arch.py
// Also see  tcg/i386/tcg-target.h:50 and target/i386/cpu.h
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
// DWARF2 register number mapping for i386, as defined
// in the System V ABI for i386 (Table 2.14: DWARF Register Number Mapping).
// See https://uclibc.org/docs/psABI-i386.pdf
static const char *const dwarf_regnames[] =
{
    "eax", "ecx", "edx", "ebx", "esp", 
    "ebp", "esi", "edi", "eip", "eflags", 
    NULL, "st0", "st1", "st2", "st3",
    "st4", "st5", "st6", "st7", NULL,
    NULL, "xmm0", "xmm1", "xmm2", "xmm3",
    "xmm4", "xmm5", "xmm6", "xmm7", "mm0", 
    "mm1", "mm2", "mm3", "mm4", "mm5", 
    "mm6", "mm7", "fcw", "fsw", "mxcsr",
    "es", "cs", "ss", "ds", "fs", 
    "gs", NULL, NULL, "tr", "ldtr"
};
static std::map<std::string, int> dwarf_regmap = {
    {"eax", R_EAX}, {"ecx", R_ECX}, {"edx", R_EDX}, {"ebx", R_EBX}, {"esp", R_ESP},
    {"ebp", R_EBP}, {"esi", R_ESI}, {"edi", R_EDI},
};
#elif defined(TARGET_X86_64)
// See here for reference of how register map was obtained.
// https://www.ucw.cz/~hubicka/papers/abi/node14.html
static const char *const dwarf_regnames[] =
{
    "rax", "rdx", "rcx", "rbx", "rsi", 
    "rdi", "rbp", "rsp", "r8",  "r9",  
    "r10", "r11", "r12", "r13", "r14", 
    "r15", "rip", "xmm0",  "xmm1",  "xmm2",  
    "xmm3", "xmm4",  "xmm5",  "xmm6",  "xmm7",
    "xmm8",  "xmm9",  "xmm10", "xmm11", "xmm12", 
    "xmm13", "xmm14", "xmm15", "st0", "st1", 
    "st2", "st3", "st4", "st5", "st6", 
    "st7", "mm0", "mm1", "mm2", "mm3",
    "mm4", "mm5", "mm6", "mm7", "rflags",
    "es", "cs", "ss", "ds", "fs", 
    "gs", NULL, NULL, "fs.base", "gs.base", 
    NULL, NULL, "tr", "ldtr", "mxcsr", 
    "fcw", "fsw"
};
static std::map<std::string, int> dwarf_regmap = {
    {"rax", R_EAX}, {"rcx", R_ECX}, {"rdx", R_EDX}, {"rbx", R_EBX}, {"rsp", R_ESP},
    {"rbp", R_EBP}, {"rsi", R_ESI}, {"rdi", R_EDI}, {"r8", 8}, {"r9", 9}, 
    {"r10", 10}, {"r11", 11}, {"r12", 12}, {"r13", 13}, {"r14", 14}, {"r15", 15},
};
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
// See here for reference of how register map was obtained.
// https://github.com/ARM-software/abi-aa/blob/main/aadwarf32/aadwarf32.rst
// See Section 4.1 DWARF register names
static const char *const dwarf_regnames[] =
{
    /*  0– 4 */
    "r0",   "r1",   "r2",   "r3",   "r4",
    /*  5– 9 */
    "r5",   "r6",   "r7",   "r8",   "r9",
    /* 10–14 */
    "r10",  "r11",  "r12",  "r13",  "r14",
    /* 15–19 */
    "r15",  NULL,   NULL,   NULL,   NULL,
    /* 20–24 */
    NULL,   NULL,   NULL,   NULL,   NULL,
    /* 25–29 */
    NULL,   NULL,   NULL,   NULL,   NULL,
    /* 30–34 */
    NULL,   NULL,   NULL,   NULL,   NULL,
    /* 35–39 */
    NULL,   NULL,   NULL,   NULL,   NULL,
    /* 40–44 */
    NULL,   NULL,   NULL,   NULL,   NULL,
    /* 45–49 */
    NULL,   NULL,   NULL,   NULL,   NULL,
    /* 50–54 */
    NULL,   NULL,   NULL,   NULL,   NULL,
    /* 55–59 */
    NULL,   NULL,   NULL,   NULL,   NULL,
    /* 60–64 */
    NULL,   NULL,   NULL,   NULL,   "s0",
    /* 65–69 */
    "s1",   "s2",   "s3",   "s4",   "s5",
    /* 70–74 */
    "s6",   "s7",   "s8",   "s9",   "s10",
    /* 75–79 */
    "s11",  "s12",  "s13",  "s14",  "s15",
    /* 80–84 */
    "s16",  "s17",  "s18",  "s19",  "s20",
    /* 85–89 */
    "s21",  "s22",  "s23",  "s24",  "s25",
    /* 90–94 */
    "s26",  "s27",  "s28",  "s29",  "s30",
    /* 95 */
    "s31"
};
static std::map<std::string, int> dwarf_regmap = {
    {"r0", 0}, {"r1", 1}, {"r2", 2}, {"r3", 3}, {"r4", 4}, 
    {"r5", 5}, {"r6", 6}, {"r7", 7}, {"r8", 8}, {"r9", 9}, 
    {"r10", 10}, {"r11", 11}, {"r12", 12}, {"r13", 13}, {"r14", 14},
    {"r15", 15},
};
#define CPU_NB_REGS 16
#elif defined(TARGET_AARCH64)
// See here for reference of how register map was obtained.
// https://github.com/ARM-software/abi-aa/blob/main/aadwarf64/aadwarf64.rst
// See Section 4.1 DWARF register names
static const char *const dwarf_regnames[] =
{
    /*  0– 4 */
    "x0",   "x1",   "x2",   "x3",   "x4",
    /*  5– 9 */
    "x5",   "x6",   "x7",   "x8",   "x9",
    /* 10–14 */
    "x10",  "x11",  "x12",  "x13",  "x14",
    /* 15–19 */
    "x15",  "x16",  "x17",  "x18",  "x19",
    /* 20–24 */
    "x20",  "x21",  "x22",  "x23",  "x24",
    /* 25–29 */
    "x25",  "x26",  "x27",  "x28",  "x29",
    /* 30–34 */
    "x30",  "sp",   "pc",   "elr",  "ra_sign_state",
    /* 35–39 */
    "tpidrro_el0", "tpidr_el0", "tpidr_el1",
    "tpidr_el2",   "tpidr_el3",
    /* 40–44 */
    NULL,   NULL,   NULL,   NULL,   NULL,
    /* 45–49 */
    NULL,   NULL,   NULL,   NULL,   NULL,
    /* 50–54 */
    NULL,   NULL,   NULL,   NULL,   NULL,
    /* 55–59 */
    NULL,   NULL,   NULL,   NULL,   NULL,
    /* 60–64 */
    NULL,   NULL,   NULL,   NULL,   "v0",
    /* 65–69 */
    "v1",   "v2",   "v3",   "v4",   "v5",
    /* 70–74 */
    "v6",   "v7",   "v8",   "v9",   "v10",
    /* 75–79 */
    "v11",  "v12",  "v13",  "v14",  "v15",
    /* 80–84 */
    "v16",  "v17",  "v18",  "v19",  "v20",
    /* 85–89 */
    "v21",  "v22",  "v23",  "v24",  "v25",
    /* 90–94 */
    "v26",  "v27",  "v28",  "v29",  "v30",
    /* 95 */
    "v31"
};
static std::map<std::string, int> dwarf_regmap = {
    {"x0", 0}, {"x1", 1}, {"x2", 2}, {"x3", 3}, {"x4", 4}, 
    {"x5", 5}, {"x6", 6}, {"x7", 7}, {"x8", 8}, {"x9", 9}, 
    {"x10", 10}, {"x11", 11}, {"x12", 12}, {"x13", 13}, {"x14", 14}, 
    {"x15", 15}, {"x16", 16}, {"x17", 17}, {"x18", 18}, {"x19", 19}, 
    {"x20", 20}, {"x21", 21}, {"x22", 22}, {"x23", 23}, {"x24", 24}, 
    {"x25", 25}, {"x26", 26}, {"x27", 27}, {"x28", 28}, {"x29", 29},
    {"x30", 30}, {"x31", 31},
};
#define CPU_NB_REGS 32
#endif

// This stuff stolen from linux-user/elfload.c
// Would have preferred to just use libelf, but QEMU stupidly
// ships an incompatible copy of elf.h so the compiler finds
// it before any other versions, making libelf unusable. Luckily
// this does not seem to affect libdwarf.

// QEMU's stupid version of elf.h
#if defined(TARGET_X86_64) || defined(TARGET_AARCH64)
    // --- 64-BIT ARCHITECTURES (X86-64 and AARCH64) ---
    #define ELF_CLASS ELFCLASS64
    #define ELF_DATA  ELFDATA2LSB
    #define Elf_Half Elf64_Half
    #define Elf_Sym  Elf64_Sym
    #define Elf_Addr Elf64_Addr
    #define ELF_R_SYM ELF64_R_SYM

    // Check for X86-64, IA-64, and AARCH64
    #define elf_check_arch(x) ( ((x) == EM_X86_64) || ((x) == EM_IA_64) || ((x) == EM_AARCH64) )

#elif (defined(TARGET_I386) && !defined(TARGET_X86_64)) || (defined(TARGET_ARM) && !defined(TARGET_AARCH64))
    // --- 32-BIT ARCHITECTURES (ARM and i386) ---
    #define ELF_CLASS ELFCLASS32
    #define ELF_DATA  ELFDATA2LSB
    #define Elf_Half Elf32_Half
    #define Elf_Sym  Elf32_Sym
    #define Elf_Addr Elf32_Addr
    #define ELF_R_SYM ELF32_R_SYM

    // Check for ARM, 386, and 486
    #define elf_check_arch(x) ( ((x) == EM_ARM) || ((x) == EM_386) || ((x) == EM_486) )
#endif

#if defined(TARGET_I386) || defined(TARGET_ARM)
// This include uses the redefined types above.
#include "elf.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
// This has function headers, things break if you move this out of this extern "C" block
#include "dwarf2_int_fns.h"
PPP_PROT_REG_CB(on_dwarf2_line_change);
}
PPP_CB_BOILERPLATE(on_dwarf2_line_change);

#define MAX_FILENAME 256
bool debug = false;
unsigned long prev_line = 0, cur_line;
target_ulong prev_function = 0, cur_function;
target_ulong prev_line_pc = 0;
std::string prev_file_name = "";
std::string prev_funct_name = std::string("");
bool inExecutableSource = false;

//////// consider putting this in pri
// current process
OsiProc *current_proc = NULL;
OsiModule *current_lib = NULL;
GArray *current_libs = NULL;
bool proc_diff(OsiProc *p_curr, OsiProc *p_new) {
    if (p_curr == NULL) {
        return (p_new != NULL);
    }
    if (p_curr->taskd != p_new->taskd
        || p_curr->asid != p_new->asid
        || p_curr->pid != p_new->pid
        || p_curr->ppid != p_new->ppid)
        return true;
    return false;
}
bool proc_changed = false;
//////// end effects plugin globals

// asid changed -- start looking for valid proc info
int asid_changed(CPUState *cpu, target_ulong old_asid, target_ulong new_asid) {
    if (current_proc) {
        free_osiproc(current_proc);
        current_proc = NULL;
        current_libs = NULL;
        current_lib = NULL;
    }
    return 0;
}
std::map <target_ulong, OsiProc> running_procs;
//std::map<std::string,std::pair<Dwarf_Addr,Dwarf_Addr>> functions;
std::map<target_ulong,std::string> funcaddrs;
//std::map<Dwarf_Addr,std::string> funcaddrs_ret;
//std::map<Dwarf_Addr,std::string> funcparams;
std::vector<std::string> processed_libs;
std::map<std::string, target_ulong> dynl_functions;
std::map<target_ulong, std::string> addr_to_dynl_function;
std::set<std::string> mods_seen;

typedef enum {
    StructType = 1,
    BaseType,
    SugarType,
    PointerType,
    ArrayType,
    ArrayRangeType,
    EnumType,
    SubroutineType,
    UnionType,
} DwarfType;
struct DwarfTypeInfo {
    DwarfType       type;
    std::string     name;
    unsigned long   size;
    std::string     fname;
    target_ulong    cu;

    DwarfTypeInfo (DwarfType ty, std::string nm, unsigned long sz, std::string fn, target_ulong cuoff) :
        type(ty), name(nm), size(sz), fname(fn), cu(cuoff) {}
    virtual ~DwarfTypeInfo() {}
};
struct RefTypeInfo : public DwarfTypeInfo {
    target_ulong    ref;

    RefTypeInfo (DwarfType ty, std::string nm, unsigned long sz, target_ulong t, std::string fn, target_ulong cuoff) :
        DwarfTypeInfo(ty, nm, sz, fn, cuoff), ref(t) {}
    virtual ~RefTypeInfo() {}
};
struct AggregateTypeInfo : public DwarfTypeInfo {
    std::map<target_ulong, std::pair<std::string, target_ulong>> children;

    AggregateTypeInfo (DwarfType ty, std::string nm, unsigned long sz, std::string fn, target_ulong cuoff) :
        DwarfTypeInfo(ty, nm, sz, fn, cuoff) {}
    virtual ~AggregateTypeInfo() {}
};
struct ArrayInfo : public RefTypeInfo {
    std::vector<target_ulong>   ranges;

    // Array size = element size * (range cnt) *...
    ArrayInfo (DwarfType ty, std::string nm, target_ulong t, std::string fn, target_ulong cuoff) :
        RefTypeInfo(ty, nm, 0, t, fn, cuoff) {}
    virtual ~ArrayInfo() {}
};
std::map<std::string, \
        std::map<target_ulong, std::map<target_ulong, DwarfTypeInfo*>>> type_map; // cu -> offset -> DwarfTypeInfo

struct VarInfo {
    target_ulong cu;
    target_ulong var_type;  // offset to type info
    std::string var_name;
    target_ulong    lowpc;
    target_ulong    highpc;
    target_ulong    dec_line;
    Json::Value     loc_ops;
    std::string fname;

    VarInfo(target_ulong cu, target_ulong var_type, std::string var_name,
            target_ulong lowpc, target_ulong highpc, Json::Value ops, target_ulong dl, std::string fn) :
        cu(cu), var_type(var_type), var_name(var_name),
        lowpc(lowpc), highpc(highpc), dec_line(dl), loc_ops(ops), fname(fn) {}
    VarInfo() {}
};

std::map<target_ulong, std::vector<VarInfo>> funcvars;
std::vector<VarInfo> global_var_list;
// don't really need this but why not
typedef struct Lib {
    std::string libname;
    target_ulong lowpc, highpc;

    friend std::ostream &operator<<(std::ostream &os, const Lib &lib) {
        os << "0x" << std::hex << lib.lowpc << "-0x" << std::hex << lib.highpc << "," << lib.libname;
        return os;
    }

    Lib(std::string libname, target_ulong lowpc, target_ulong highpc) :
        libname(libname), lowpc(lowpc), highpc(highpc) {
        assert(lowpc < highpc);
        }

    bool operator <(const Lib &lib) const {
        return this->lowpc < lib.lowpc;
    }
} Lib;
std::vector<Lib> active_libs;

typedef struct LineRange {
    target_ulong lowpc, highpc, function_addr;
    std::string filename;
    unsigned long line_number;
    unsigned long line_off;

    friend std::ostream &operator<<(std::ostream &os, const LineRange &lr) {
        os << "0x" << std::hex << lr.lowpc << "-0x" << std::hex << lr.highpc <<
            lr.filename << ":" << lr.line_number << ":" << lr.line_off;
        return os;
    }

    LineRange(target_ulong lowpc, target_ulong highpc, unsigned long line_number,
            std::string filename, target_ulong function_addr, unsigned long line_off) :
        lowpc(lowpc), highpc(highpc), function_addr(function_addr),
        filename(filename), line_number(line_number), line_off(line_off) {
        assert(lowpc <= highpc);
   }
} LineRange;
std::vector<LineRange> line_range_list;
std::vector<LineRange> fn_start_line_range_list;
std::map<std::string, LineRange> fn_name_to_line_info;

// don't need this, but may want it in the future
//std::map<Dwarf_Addr, Dwarf_Unsigned> funct_to_cu_base;
// use this to calculate a the value of a function's base pointer at a given pc
// curfunction -> location description list for FP
std::map<target_ulong,Json::Value> funct_to_framepointers;


#define ENUM_OPS(X) \
    X(DW_OP_lit0),  \
    X(DW_OP_lit1),  \
    X(DW_OP_lit2),  \
    X(DW_OP_lit3),  \
    X(DW_OP_lit4),  \
    X(DW_OP_lit5),  \
    X(DW_OP_lit6),  \
    X(DW_OP_lit7),  \
    X(DW_OP_lit8),  \
    X(DW_OP_lit9),  \
    X(DW_OP_lit10), \
    X(DW_OP_lit11), \
    X(DW_OP_lit12), \
    X(DW_OP_lit13), \
    X(DW_OP_lit14), \
    X(DW_OP_lit15), \
    X(DW_OP_lit16), \
    X(DW_OP_lit17), \
    X(DW_OP_lit18), \
    X(DW_OP_lit19), \
    X(DW_OP_lit20), \
    X(DW_OP_lit21), \
    X(DW_OP_lit22), \
    X(DW_OP_lit23), \
    X(DW_OP_lit24), \
    X(DW_OP_lit25), \
    X(DW_OP_lit26), \
    X(DW_OP_lit27), \
    X(DW_OP_lit28), \
    X(DW_OP_lit29), \
    X(DW_OP_lit30), \
    X(DW_OP_lit31), \
    X(DW_OP_addr),  \
    X(DW_OP_const1u),   \
    X(DW_OP_const1s),   \
    X(DW_OP_const2u),   \
    X(DW_OP_const2s),   \
    X(DW_OP_const4u),   \
    X(DW_OP_const4s),   \
    X(DW_OP_const8u),   \
    X(DW_OP_const8s),   \
    X(DW_OP_constu),    \
    X(DW_OP_consts),    \
    X(DW_OP_reg0),  \
    X(DW_OP_reg1),  \
    X(DW_OP_reg2),  \
    X(DW_OP_reg3),  \
    X(DW_OP_reg4),  \
    X(DW_OP_reg5),  \
    X(DW_OP_reg6),  \
    X(DW_OP_reg7),  \
    X(DW_OP_reg8),  \
    X(DW_OP_reg9),  \
    X(DW_OP_reg10), \
    X(DW_OP_reg11), \
    X(DW_OP_reg12), \
    X(DW_OP_reg13), \
    X(DW_OP_reg14), \
    X(DW_OP_reg15), \
    X(DW_OP_reg16), \
    X(DW_OP_reg17), \
    X(DW_OP_reg18), \
    X(DW_OP_reg19), \
    X(DW_OP_reg20), \
    X(DW_OP_reg21), \
    X(DW_OP_reg22), \
    X(DW_OP_reg23), \
    X(DW_OP_reg24), \
    X(DW_OP_reg25), \
    X(DW_OP_reg26), \
    X(DW_OP_reg27), \
    X(DW_OP_reg28), \
    X(DW_OP_reg29), \
    X(DW_OP_reg30), \
    X(DW_OP_reg31), \
    X(DW_OP_regx),  \
    X(DW_OP_breg0), \
    X(DW_OP_breg1), \
    X(DW_OP_breg2), \
    X(DW_OP_breg3), \
    X(DW_OP_breg4), \
    X(DW_OP_breg5), \
    X(DW_OP_breg6), \
    X(DW_OP_breg7), \
    X(DW_OP_breg8), \
    X(DW_OP_breg9), \
    X(DW_OP_breg10),    \
    X(DW_OP_breg11),    \
    X(DW_OP_breg12),    \
    X(DW_OP_breg13),    \
    X(DW_OP_breg14),    \
    X(DW_OP_breg15),    \
    X(DW_OP_breg16),    \
    X(DW_OP_breg17),    \
    X(DW_OP_breg18),    \
    X(DW_OP_breg19),    \
    X(DW_OP_breg20),    \
    X(DW_OP_breg21),    \
    X(DW_OP_breg22),    \
    X(DW_OP_breg23),    \
    X(DW_OP_breg24),    \
    X(DW_OP_breg25),    \
    X(DW_OP_breg26),    \
    X(DW_OP_breg27),    \
    X(DW_OP_breg28),    \
    X(DW_OP_breg29),    \
    X(DW_OP_breg30),    \
    X(DW_OP_breg31),    \
    X(DW_OP_fbreg), \
    X(DW_OP_bregx), \
    X(DW_OP_dup),   \
    X(DW_OP_drop),  \
    X(DW_OP_pick),  \
    X(DW_OP_over),  \
    X(DW_OP_stack_value),   \
    X(DW_OP_rot),   \
    X(DW_OP_GNU_entry_value),   \
    X(DW_OP_GNU_convert),   \
    X(DW_OP_convert),   \
    X(DW_OP_piece), \
    X(DW_OP_bit_piece), \
    X(DW_OP_deref_type),    \
    X(DW_OP_GNU_deref_type),    \
    X(DW_OP_deref), \
    X(DW_OP_deref_size),    \
    X(DW_OP_abs),   \
    X(DW_OP_neg),   \
    X(DW_OP_not),   \
    X(DW_OP_plus_uconst),   \
    X(DW_OP_and),   \
    X(DW_OP_div),   \
    X(DW_OP_minus), \
    X(DW_OP_mod),   \
    X(DW_OP_mul),   \
    X(DW_OP_or),    \
    X(DW_OP_plus),  \
    X(DW_OP_shl),   \
    X(DW_OP_shr),   \
    X(DW_OP_shra),  \
    X(DW_OP_xor),   \
    X(DW_OP_le),    \
    X(DW_OP_ge),    \
    X(DW_OP_eq),    \
    X(DW_OP_lt),    \
    X(DW_OP_gt),    \
    X(DW_OP_ne),    \
    X(DW_OP_skip),  \
    X(DW_OP_bra),   \
    X(DW_OP_nop)

typedef enum {
    Dummy = 0,
#define T(E) E
    ENUM_OPS(T)
#undef T
} DW_OPS;
std::map<std::string, DW_OPS> DW_OP_HELPER = {
#define T(X) {#X, X}
    ENUM_OPS(T)
#undef T
};

/* Decode a DW_OP stack program.  Place top of stack in ret_loc.  Push INITIAL
   onto the stack to start.  Return the location type: memory address, register,
   or const value representing value of variable*/
LocType execute_stack_op(CPUState *cpu, target_ulong pc, Json::Value ops,
        target_ulong frame_ptr, target_ulong *ret_loc) {
    target_ulong stack[64];	/* ??? Assume this is enough.  */
    int stack_elt, loc_idx;
    target_ulong result;
    bool inReg = false;
    stack[0] = 0;
    stack_elt = 1;
    loc_idx = 0;
    std::string register_name = "";
    while (loc_idx < ops.size()) {
        target_ulong reg;
        target_long offset;
        std::string cur_op = ops[loc_idx].asString();
        DW_OPS op = DW_OP_HELPER[cur_op];
        loc_idx++;
        dprintf("[dwarf2][execute_stack_op] cur_op %x\n", op);
        switch (op) {
            case DW_OP_lit0:
            case DW_OP_lit1:
            case DW_OP_lit2:
            case DW_OP_lit3:
            case DW_OP_lit4:
            case DW_OP_lit5:
            case DW_OP_lit6:
            case DW_OP_lit7:
            case DW_OP_lit8:
            case DW_OP_lit9:
            case DW_OP_lit10:
            case DW_OP_lit11:
            case DW_OP_lit12:
            case DW_OP_lit13:
            case DW_OP_lit14:
            case DW_OP_lit15:
            case DW_OP_lit16:
            case DW_OP_lit17:
            case DW_OP_lit18:
            case DW_OP_lit19:
            case DW_OP_lit20:
            case DW_OP_lit21:
            case DW_OP_lit22:
            case DW_OP_lit23:
            case DW_OP_lit24:
            case DW_OP_lit25:
            case DW_OP_lit26:
            case DW_OP_lit27:
            case DW_OP_lit28:
            case DW_OP_lit29:
            case DW_OP_lit30:
            case DW_OP_lit31:
                result = op - DW_OP_lit0;
                break;

            case DW_OP_addr:
                //printf(" DW_OP_addr: 0x%llx\n", cur_loc->lr_number);
                result = ops[loc_idx].asUInt64();
                loc_idx++;
                //op_ptr += sizeof (void *);
                break;

            case DW_OP_const1u:
                result = ops[loc_idx].asUInt64();
                loc_idx++;
                //result = read_1u (cur_loc->lr_number);
                //op_ptr += 1;
                break;
            case DW_OP_const1s:
                result = ops[loc_idx].asInt64();
                loc_idx++;
                //result = read_1s (cur_loc->lr_number);
                //op_ptr += 1;
                break;
            case DW_OP_const2u:
                result = ops[loc_idx].asUInt64();
                loc_idx++;
                //result = read_2u (cur_loc->lr_number);
                //op_ptr += 2;
                break;
            case DW_OP_const2s:
                result = ops[loc_idx].asInt64();
                loc_idx++;
                //result = read_2s (cur_loc->lr_number);
                //op_ptr += 2;
                break;
            case DW_OP_const4u:
                result = ops[loc_idx].asUInt64();
                loc_idx++;
                //result = read_4u (cur_loc->lr_number);
                //op_ptr += 4;
                break;
            case DW_OP_const4s:
                result = ops[loc_idx].asInt64();
                loc_idx++;
                //result = read_4s (cur_loc->lr_number);
                //op_ptr += 4;
                break;
            case DW_OP_const8u:
                result = ops[loc_idx].asUInt64();
                loc_idx++;
                //result = read_8u (cur_loc->lr_number);
                //op_ptr += 8;
                break;
            case DW_OP_const8s:
                result = ops[loc_idx].asInt64();
                loc_idx++;
                //result = read_8s (cur_loc->lr_number);
                //op_ptr += 8;
                break;
            case DW_OP_constu:
                result = ops[loc_idx].asUInt64();
                loc_idx++;
                //read_uleb128 (cur_loc->lr_number, &result);
                break;
            case DW_OP_consts:
                result = ops[loc_idx].asInt64();
                loc_idx++;
                //read_sleb128 (cur_loc->lr_number, &stmp);
                break;

            case DW_OP_reg0:
            case DW_OP_reg1:
            case DW_OP_reg2:
            case DW_OP_reg3:
            case DW_OP_reg4:
            case DW_OP_reg5:
            case DW_OP_reg6:
            case DW_OP_reg7:
            case DW_OP_reg8:
            case DW_OP_reg9:
            case DW_OP_reg10:
            case DW_OP_reg11:
            case DW_OP_reg12:
            case DW_OP_reg13:
            case DW_OP_reg14:
            case DW_OP_reg15:
            case DW_OP_reg16:
            case DW_OP_reg17:
            case DW_OP_reg18:
            case DW_OP_reg19:
            case DW_OP_reg20:
            case DW_OP_reg21:
            case DW_OP_reg22:
            case DW_OP_reg23:
            case DW_OP_reg24:
            case DW_OP_reg25:
            case DW_OP_reg26:
            case DW_OP_reg27:
            case DW_OP_reg28:
            case DW_OP_reg29:
            case DW_OP_reg30:
            case DW_OP_reg31:
                register_name = dwarf_regnames[op - DW_OP_reg0];
                result = dwarf_regmap[register_name];
                dprintf("[dwarf2][execute_stack_op] register name: %s and result %ld\n", register_name.c_str(), result);
                inReg = true;
                break;
            case DW_OP_regx:
                result = ops[loc_idx].asUInt64();
                loc_idx++;
                inReg = true;
                break;

            case DW_OP_breg0:
            case DW_OP_breg1:
            case DW_OP_breg2:
            case DW_OP_breg3:
            case DW_OP_breg4:
            case DW_OP_breg5:
            case DW_OP_breg6:
            case DW_OP_breg7:
            case DW_OP_breg8:
            case DW_OP_breg9:
            case DW_OP_breg10:
            case DW_OP_breg11:
            case DW_OP_breg12:
            case DW_OP_breg13:
            case DW_OP_breg14:
            case DW_OP_breg15:
            case DW_OP_breg16:
            case DW_OP_breg17:
            case DW_OP_breg18:
            case DW_OP_breg19:
            case DW_OP_breg20:
            case DW_OP_breg21:
            case DW_OP_breg22:
            case DW_OP_breg23:
            case DW_OP_breg24:
            case DW_OP_breg25:
            case DW_OP_breg26:
            case DW_OP_breg27:
            case DW_OP_breg28:
            case DW_OP_breg29:
            case DW_OP_breg30:
            case DW_OP_breg31:
                offset = ops[loc_idx].asInt64();
                loc_idx++;
                result = getReg(cpu, op - DW_OP_breg0) + offset;
                break;
            case DW_OP_fbreg:
                offset = ops[loc_idx].asInt64();
                loc_idx++;
                // frame pointer
                dprintf("[dwarf2][execute_stack_op] fp [0x%lx] + offset: %ld\n", frame_ptr, offset);
                result = frame_ptr + offset;
                break;
            case DW_OP_bregx:
                reg = ops[loc_idx].asUInt64();
                loc_idx++;
                offset = ops[loc_idx].asInt64();
                loc_idx++;
                result = getReg(cpu, reg) + offset;
                break;

            case DW_OP_dup:
                if (stack_elt < 1) {
                    assert (1==0);
                }
                result = stack[stack_elt - 1];
                break;

            case DW_OP_drop:
                if (--stack_elt < 0) {
                    assert (1==0);
                }
                goto no_push;

            case DW_OP_pick:
                offset = ops[loc_idx].asInt64();
                loc_idx++;
                //offset = *op_ptr++;
                if (offset >= stack_elt - 1) {
                    assert (1==0);
                }
                result = stack[stack_elt - 1 - offset];
                break;

            case DW_OP_over:
                if (stack_elt < 2) {
                    assert (1==0);
                }
                result = stack[stack_elt - 2];
                break;
           
            // variable doesn't have location
            // but dwarf information says it's VALUE
            // at this point in the program
            case DW_OP_stack_value:
                if (stack_elt < 1) {
                    assert (1==0);
                }
                *ret_loc = stack[stack_elt - 1];
                return LocConst;
                break;
            case DW_OP_rot:
                {
                    target_ulong t1, t2, t3;
                    if (stack_elt < 3) {
                        assert (1==0);
                    }
                    t1 = stack[stack_elt - 1];
                    t2 = stack[stack_elt - 2];
                    t3 = stack[stack_elt - 3];
                    stack[stack_elt - 1] = t2;
                    stack[stack_elt - 2] = t3;
                    stack[stack_elt - 3] = t1;
                    goto no_push;
                }
            case DW_OP_GNU_entry_value:
                //printf(" DW_OP_entry_value: Must figure out stack unwinding. Not implemented. Returning LocErr\n");
                return LocErr;
            // takes an argument (which is offset into debugging information for a die entry that is a base type
            // converts arg on top of stack to said base type
            case DW_OP_GNU_convert:
            case DW_OP_convert:
                //printf(" DW_OP_[GNU]_convert: Top of stack must be cast to different type.  Not implemented. Returning LocErr\n");
                return LocErr;
            case DW_OP_piece:
            case DW_OP_bit_piece:
                //printf(" DW_OP_[bit]_piece: Variable is split among multiple locations/registers. Not implemented. Returning LocErr\n");
                return LocErr;
            case DW_OP_deref_type:
            case DW_OP_GNU_deref_type:
            case DW_OP_deref:
            case DW_OP_deref_size:
            case DW_OP_abs:
            case DW_OP_neg:
            case DW_OP_not:
            case DW_OP_plus_uconst:
                /* Unary operations.  */
                if (--stack_elt < 0) {
                    assert (1==0);
                }
                result = stack[stack_elt];

                switch (op) {
                    case DW_OP_deref:
                        {
                            result = read_guest_pointer (cpu, result);
                        }
                        break;
                    case DW_OP_deref_size:
                        {
                            target_ulong sz = ops[loc_idx].asUInt64();
                            loc_idx++;
                            switch (sz) {
                                case 1:
                                    result = read_1u (cpu, result);
                                    break;
                                case 2:
                                    result = read_2u (cpu, result);
                                    break;
                                case 4:
                                    result = read_4u (cpu, result);
                                    break;
                                case 8:
                                    result = read_8u (cpu, result);
                                    break;
                                default:
                                    assert (1==0);
                            }
                        }
                        break;
            
                    case DW_OP_GNU_deref_type:
                    case DW_OP_deref_type:
                        //printf(" DW_OP_[GNU]_deref_type: need to dereference an address with a particular type\n");
                        return LocErr;

                    case DW_OP_abs:
                        if ((target_long) result < 0) {
                            result = -result;
                        }
                        break;
                    case DW_OP_neg:
                        result = -result;
                        break;
                    case DW_OP_not:
                        result = ~result;
                        break;
                    case DW_OP_plus_uconst:
                        result += ops[loc_idx].asUInt64();
                        loc_idx++;
                        break;

                    default:
                        assert (1==0);
                }
                break;

            case DW_OP_and:
            case DW_OP_div:
            case DW_OP_minus:
            case DW_OP_mod:
            case DW_OP_mul:
            case DW_OP_or:
            case DW_OP_plus:
            case DW_OP_shl:
            case DW_OP_shr:
            case DW_OP_shra:
            case DW_OP_xor:
            case DW_OP_le:
            case DW_OP_ge:
            case DW_OP_eq:
            case DW_OP_lt:
            case DW_OP_gt:
            case DW_OP_ne:
                {
                    /* Binary operations.  */
                    target_ulong first, second;
                    if ((stack_elt -= 2) < 0) {
                        assert (1==0);
                    }
                    second = stack[stack_elt];
                    first = stack[stack_elt + 1];

                    switch (op) {
                        case DW_OP_and:
                            result = second & first;
                            break;
                        case DW_OP_div:
                            result = (target_long) second / (target_long) first;
                            break;
                        case DW_OP_minus:
                            result = second - first;
                            break;
                        case DW_OP_mod:
                            result = (target_long) second % (target_long) first;
                            break;
                        case DW_OP_mul:
                            result = second * first;
                            break;
                        case DW_OP_or:
                            result = second | first;
                            break;
                        case DW_OP_plus:
                            result = second + first;
                            break;
                        case DW_OP_shl:
                            result = second << first;
                            break;
                        case DW_OP_shr:
                            result = second >> first;
                            break;
                        case DW_OP_shra:
                            result = (target_long) second >> first;
                            break;
                        case DW_OP_xor:
                            result = second ^ first;
                            break;
                        case DW_OP_le:
                            result = (target_long) first <= (target_long) second;
                            break;
                        case DW_OP_ge:
                            result = (target_long) first >= (target_long) second;
                            break;
                        case DW_OP_eq:
                            result = (target_long) first == (target_long) second;
                            break;
                        case DW_OP_lt:
                            result = (target_long) first < (target_long) second;
                            break;
                        case DW_OP_gt:
                            result = (target_long) first > (target_long) second;
                            break;
                        case DW_OP_ne:
                            result = (target_long) first != (target_long) second;
                            break;

                        default:
                            assert (1==0);
                    }
                }
                break;

            case DW_OP_skip:
                assert (1==0);  // TODO
                //offset = cur_loc->lr_offset;
                //stmp = cur_loc->lr_number;
                //next_offset = offset + 1 + 2 + stmp;
                //for (i = 0; i < loc_cnt; i++) {
                //    if (loc_list[i].lr_offset == next_offset) {
                //        loc_idx = i;
                //        goto no_push;
                //    }
                //}
                //return LocErr;
                assert (1==0);

            case DW_OP_bra:
                assert (1==0); // TODO
                //if (--stack_elt < 0)
                //    assert (1==0);
                //offset = cur_loc->lr_offset;
                //stmp = cur_loc->lr_number;
                //next_offset = offset + 1 + 2 + stmp;
                //if (stack[stack_elt] != 0) {
                //    for (i = 0; i < loc_cnt; i++) {
                //        if (loc_list[i].lr_offset == next_offset) {
                //            loc_idx = i;
                //            goto no_push;
                //        }
                //    }
                //    //return LocErr;
                //    assert (1==0);
                //}
                goto no_push;

            case DW_OP_nop:
                goto no_push;

            default:
                return LocErr;
        }

        /* Most things push a result value.  */
        if ((size_t) stack_elt >= sizeof(stack)/sizeof(*stack)) {
            assert (1==0);
        }
        stack[stack_elt++] = result;
no_push:;
    }

    /* We were executing this program to get a value.  It should be
       at top of stack.  */
    if (--stack_elt < 0) {
        assert (1==0);
    }
    *ret_loc = stack[stack_elt];
    if (inReg) {
        return LocReg;
    }
    else {
        return LocMem;
    }
}

bool sortRange(const LineRange &x1, const LineRange &x2) {
    /*
     * if (x1.lowpc < x2.lowpc) return true;
     * else if (x1.lowpc > x2.lowpc) return false;
     * return x1.highpc < x2.highpc;
     */
    return std::tie(x1.lowpc, x1.highpc) < std::tie(x2.lowpc, x2.highpc);
}

struct CompareRangeAndPC {
    bool operator () (const LineRange &ln_info,
                    const target_ulong &pc) const {
        if (ln_info.lowpc <= pc && ln_info.highpc > pc) {
            return false;
        }
        else {
            return ln_info.lowpc < pc;
        }
    }
};

// see pri_dwarf.proto
void pri_dwarf_plog(const char *file_callee, const char *fn_callee, uint64_t lno_callee,
        const char *file_caller, uint64_t lno_caller, bool isCall) {
    // don't log hypercalls.
    if (strstr(file_callee, "pirate_mark_lava.h")) {
        return;
    }
    if (strstr(file_callee, "hypercall.h")) {
        return;
    }

    // setup
    Panda__DwarfCall *dwarf = (Panda__DwarfCall *) malloc (sizeof (Panda__DwarfCall));
    *dwarf = PANDA__DWARF_CALL__INIT;
    // assign values
    // these (char *) casts are ugly
    dwarf->function_name_callee = (char *) fn_callee;
    dwarf->file_callee = (char *) file_callee;
    dwarf->line_number_callee = lno_callee;
    dwarf->file_caller = (char *) file_caller;
    dwarf->line_number_caller = lno_caller;

    Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
    // create a call or ret message
    if (isCall) {
        ple.dwarf2_call = dwarf;
    }
    else {
        ple.dwarf2_ret = dwarf;
    }
    // write to log file
    if (pandalog) {
        pandalog_write_entry(&ple);
    }
    free(dwarf);
}

target_ulong prev_pc = 0;
uint32_t prev_pc_count = 0;


void die(const char* fmt, ...) {
    va_list args;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    vfprintf(stdout, fmt, args);
    va_end(args);
}

static bool elf_check_ident(struct elfhdr *ehdr) {
    return (ehdr->e_ident[EI_MAG0] == ELFMAG0
            && ehdr->e_ident[EI_MAG1] == ELFMAG1
            && ehdr->e_ident[EI_MAG2] == ELFMAG2
            && ehdr->e_ident[EI_MAG3] == ELFMAG3
            && ehdr->e_ident[EI_CLASS] == ELF_CLASS
            && ehdr->e_ident[EI_DATA] == ELF_DATA
            && ehdr->e_ident[EI_VERSION] == EV_CURRENT);
}

static bool elf_check_ehdr(struct elfhdr *ehdr) {
    return (elf_check_arch(ehdr->e_machine)
            && ehdr->e_ehsize == sizeof(struct elfhdr)
            && ehdr->e_phentsize == sizeof(struct elf_phdr)
            && ehdr->e_shentsize == sizeof(struct elf_shdr)
            && (ehdr->e_type == ET_EXEC || ehdr->e_type == ET_DYN));
}

uint64_t elf_get_baseaddr(const char *fname, const char *basename, target_ulong actual_base_address) {
    struct elfhdr ehdr;
    Elf_Half shstrndx;
    Elf_Addr load_addr, loaddr, hiaddr;
    int i, retval;

    FILE *f = fopen(fname, "rb");
    if (0 == fread(&ehdr, sizeof(ehdr), 1, f)) {
        printf("Read 0 bytes from file\n");
        return -1;
    }

    /* First of all, some simple consistency checks */
    if (!elf_check_ident(&ehdr)) {
        return -1;
    }
    if (!elf_check_ehdr(&ehdr)) {
        return -1;
    }

    std::unique_ptr<elf_phdr[]> phdr(new elf_phdr[ehdr.e_phnum]);
    fseek(f, ehdr.e_phoff, SEEK_SET);
    retval = fread(phdr.get(), sizeof(struct elf_phdr), ehdr.e_phnum, f);
    if (retval != ehdr.e_phnum) {
        return -1;
    }

    std::unique_ptr<elf_shdr[]> shdr(new elf_shdr[ehdr.e_shnum]);
    fseek(f, ehdr.e_shoff, SEEK_SET);
    retval = fread(shdr.get(), sizeof(struct elf_shdr), ehdr.e_shnum, f);
    if (retval != ehdr.e_shnum) {
        return -1;
    }
    shstrndx = ehdr.e_shstrndx;
    if (shstrndx == SHN_UNDEF) {
        printf("no section table\n");
        return -1;
    }
    else if (shstrndx == SHN_HIRESERVE) {
        printf("Actual index for string table is in sh_link of string table section\n");
        return -1;
    }

    std::unique_ptr<char[]> shstrtable(new char[shdr[ehdr.e_shstrndx].sh_size]);
    fseek(f, shdr[ehdr.e_shstrndx].sh_offset, SEEK_SET);
    if (shdr[ehdr.e_shstrndx].sh_size != fread(shstrtable.get(), 1,  shdr[ehdr.e_shstrndx].sh_size, f)) {
        printf("Wasn't able to successfully read string table from file\n");
        return -1;
    }

    // analyze section headers for .rel.plt section
    // and .plt (SHT_PROGBITS) for base address of dynamically linked function names
    ssize_t relplt_size = 0;
    ELF_RELOC *relplt = NULL;
    Elf_Sym *symtab = NULL;
    Elf_Sym *dynsym = NULL;
    char *strtable = NULL;
    char *dynstrtable = NULL;
    Elf_Addr plt_addr=0;
    bool initialized_plt_addr = false;
    for (i = 0; i < ehdr.e_shnum; ++i) {
        if (strcmp(".plt", &shstrtable[shdr[i].sh_name]) == 0) {
            plt_addr = shdr[i].sh_addr + 0x10;
            initialized_plt_addr = true;
        }
        else if (strcmp(".strtab", &shstrtable[shdr[i].sh_name]) == 0) {
            strtable= (char *) malloc(shdr[i].sh_size);
            fseek(f, shdr[i].sh_offset, SEEK_SET);
            if (shdr[i].sh_size != fread(strtable, 1, shdr[i].sh_size, f)) {
                printf("Wasn't able to successfully populate the strtable\n");
                return -1;
            }
        }
        else if (strcmp(".dynstr", &shstrtable[shdr[i].sh_name]) == 0) {
            dynstrtable= (char *) malloc(shdr[i].sh_size);
            fseek(f, shdr[i].sh_offset, SEEK_SET);
            if (shdr[i].sh_size != fread(dynstrtable, 1, shdr[i].sh_size, f)) {
                printf("Wasn't able to successfully populate the dynstrtable\n");
                return -1;
            }
        }
        else if (strcmp(".rel.plt", &shstrtable[shdr[i].sh_name]) == 0) {
            relplt = (ELF_RELOC *) malloc(shdr[i].sh_size);
            relplt_size = shdr[i].sh_size/sizeof(ELF_RELOC);
            fseek(f, shdr[i].sh_offset, SEEK_SET);
            if (shdr[i].sh_size != fread(relplt, 1, shdr[i].sh_size, f)) {
                printf("Wasn't able to successfully populate the reltab\n");
                return -1;
            }
        }
        else if (strcmp(".dynsym", &shstrtable[shdr[i].sh_name]) == 0) {
            dynsym = (Elf_Sym *) malloc(shdr[i].sh_size);
            fseek(f, shdr[i].sh_offset, SEEK_SET);
            if (shdr[i].sh_size != fread(dynsym, 1, shdr[i].sh_size, f)) {
                printf("Wasn't able to successfully populate the .dynsym\n");
                return -1;
            }
        }
        else if (strcmp(".symtab", &shstrtable[shdr[i].sh_name]) == 0) {
            symtab = (Elf_Sym *) malloc(shdr[i].sh_size);
            fseek(f, shdr[i].sh_offset, SEEK_SET);
            if (shdr[i].sh_size != fread(symtab, 1, shdr[i].sh_size, f)) {
                printf("Wasn't able to successfully populate the symtab\n");
                return -1;
            }
        }
    }

    if (!initialized_plt_addr) {
        printf("Wasn't able to successfully identify plt_addr\n");
        abort();
    }
    /* Find the maximum size of the image and allocate an appropriate
       amount of memory to handle that.  */
    loaddr = -1;
    for (i = 0; i < ehdr.e_phnum; ++i) {
        if (phdr[i].p_type == PT_LOAD) {
            Elf_Addr a = phdr[i].p_vaddr;
            if (a < loaddr) {
                loaddr = a;
            }
            a += phdr[i].p_memsz;
            if (a > hiaddr) {
                hiaddr = a;
            }
        }
    }
    // load address is the low addr
    load_addr = loaddr;
    bool norelro = (actual_base_address == 0 || load_addr == actual_base_address);
    //printf("load addr: 0x%x\n", load_addr);
    // check if there is a .plt and a dynamic str table
    if (relplt == NULL || dynsym == NULL || dynstrtable == NULL) {
        return load_addr;
    }
    // put libname in the a processed_libs list to iterate through when we process the function later on
    processed_libs.push_back(std::string(basename));
    // now add plt functions to global plt function mapping
    target_ulong plt_fun_addr;
    std::string plt_fun_name;
    for (i = 0; i < relplt_size; i++) {
        if (norelro) {
            plt_fun_addr = (target_ulong) plt_addr+16*i;
        }
        else {
            plt_fun_addr = (target_ulong) plt_addr+16*i + actual_base_address;
        }
        uint32_t f_name_strndx = dynsym[ELF_R_SYM(relplt[i].r_info)].st_name;
        plt_fun_name = std::string(&dynstrtable[f_name_strndx]);
        //printf(" [%d] r_offset: %x, .text location: %x,  sym_name: %s\n", i, relplt[i].r_offset, plt_addr+16*i,  &dynstrtable[f_name_strndx]);
        // check if we have already processed this symbol name
        auto it = fn_name_to_line_info.find(plt_fun_name);
        // if plt_fun_name has already been processed in the dwarf compilation
        // unit of some other executable, then add it to line_range_list
        if (it != fn_name_to_line_info.end()) {
            const LineRange &lr = it->second;
            line_range_list.push_back(LineRange(plt_fun_addr, plt_fun_addr,
                        lr.line_number, lr.filename, lr.function_addr, lr.line_off));
        }
        else {
            dynl_functions[std::string(basename) + ":plt!" + plt_fun_name] = plt_fun_addr;
            addr_to_dynl_function[plt_fun_addr] = "plt!" + plt_fun_name;
            funcaddrs[plt_fun_addr] = std::string(basename) + ":plt!" + plt_fun_name;
        }
    }
    // sort the line_range_list because we changed it
    std::sort(line_range_list.begin(), line_range_list.end(), sortRange);
    return load_addr;
}

int die_get_type_size (DwarfTypeInfo *ty) {

    // initialize tag to DW_TAG_pointer_type to enter the while loop
    while (ty->type == SugarType) {
        ty = type_map[ty->fname][ty->cu][((RefTypeInfo*)ty)->ref];
    }
    switch (ty->type) {
        case EnumType:
        case UnionType: // union has byte_size field like structure_type and base_type
        case StructType:
        case BaseType:
            // hit base_type, do taint based on size of base type
            return ty->size;
        //case DW_TAG_ptr_to_member_type: // what to do here?
        case PointerType: // increment derefs
            return sizeof(target_ulong);
        case ArrayType:
            {
                ArrayInfo *arrty = (ArrayInfo*)ty;
                target_ulong array_size = 0;
                for (auto r : arrty->ranges) {
                    DwarfTypeInfo *rty = type_map[arrty->fname][arrty->cu][r];
                    assert (rty->type == ArrayRangeType);
                    if (!array_size) {
                        array_size = rty->size;
                    }
                    else {
                        array_size *= rty->size;
                    }
                }
                //printf("Querying: ([]) %s\n", cur_astnodename.c_str());
                DwarfTypeInfo *refty = type_map[arrty->fname][arrty->cu][arrty->ref];
                target_ulong elem_typesize = die_get_type_size(refty);
                // array size is 0 than we likely have a 0 length
                // array which is common at the end of structs to make a
                // flexible length struct
                array_size = array_size == 0 ? 1 : array_size;
                return array_size*elem_typesize;
            }
        default:
            return -1;
    }
    return -1;
}

void __dwarf_type_iter(CPUState *cpu, target_ulong base_addr, LocType loc_t,
        std::string astnodename, DwarfTypeInfo *ty, dwarfTypeCB cb, int recursion_level);

void dwarf2_type_iter(CPUState *cpu, target_ulong base_addr, LocType loc_t, DwarfVarType *var_ty, dwarfTypeCB cb,
        int recursion_level) {
    if (var_ty->dec_line >= cur_line)
        return;

    __dwarf_type_iter(cpu, base_addr, loc_t, "&" + var_ty->nodename, var_ty->type, cb, recursion_level);
    return;
}
void __dwarf_type_iter (CPUState *cpu, target_ulong base_addr, LocType loc_t,
        std::string astnodename, DwarfTypeInfo *ty, dwarfTypeCB cb, int recursion_level) {
    if (recursion_level <= 0) {
        return;
    }
    int rc;
    std::string cur_astnodename = astnodename;
    target_ulong cur_base_addr = base_addr;
    CPUArchState *env = (CPUArchState*) cpu->env_ptr;
    dprintf("Calling __dwarf_type_iter: %s\n", cur_astnodename.c_str());

    // initialize tag to DW_TAG_pointer_type to enter the while loop
    DwarfType tag = ty->type;
    while (tag == PointerType   ||
           tag == SugarType     ||
           tag == ArrayType     ||
           tag == EnumType      ||
           tag == BaseType      ||
           tag == StructType    ||
           tag == SubroutineType ||
           tag == UnionType) {
        switch (tag) {
            case StructType:
                dprintf("  [+] structure_type: enumerating . . .\n");
                {
                    dprintf("Querying: (Struct) %s\n", cur_astnodename.c_str());
                    AggregateTypeInfo *aty = (AggregateTypeInfo*)ty;
                    cb(cpu, cur_base_addr, loc_t, aty->size, cur_astnodename.c_str());
                    if (cur_astnodename.find("&") == 0) {
                        cur_astnodename  = cur_astnodename.substr(1);
                    }
                    else {
                        cur_astnodename = "(*" + cur_astnodename + ")";
                    }

                    for (auto c : aty->children) {
                        std::string temp_name;
                        target_ulong struct_offset = c.first;
                        std::string field_name = c.second.first;
                        temp_name = "&(" + cur_astnodename + "." + field_name + ")";
                        DwarfTypeInfo *memty = type_map[aty->fname][aty->cu][c.second.second];
                        dprintf("[dwarf2] struct: %s, offset: %lu\n", temp_name.c_str(), (unsigned long) struct_offset);
                        if (memty != nullptr) {
                            __dwarf_type_iter(cpu, cur_base_addr + struct_offset, loc_t, temp_name, memty, cb, recursion_level - 1);
                        } else {
                            dprintf("[dwarf2] Warning: Struct member '%s' type (ref 0x%llx) not found in type_map for struct '%s'. Skipping.\n",
                                field_name.c_str(), (unsigned long long) c.second.second, cur_astnodename.c_str());
                        }
                    }
                    return;
                }
            case BaseType:
                // hit base_type, do taint based on size of base type
                {
                    dprintf("Querying Base Type: %s\n", cur_astnodename.c_str());
                    cb(cpu, cur_base_addr, loc_t, ty->size < 4 ? 4 : ty->size, cur_astnodename.c_str());
                    return;
                }
            case PointerType: // increment derefs
                // check if it is a pointer to the char type, if so
                // strnlen = true and then return
                {
                    dprintf("Querying Pointer Type: (*) %s\n", cur_astnodename.c_str());
                    cb(cpu, cur_base_addr, loc_t, sizeof(cur_base_addr), cur_astnodename.c_str());
                    if (cur_astnodename.find("&") == 0) {
                        cur_astnodename  = cur_astnodename.substr(1);
                    }
                    else {
                        cur_astnodename = "*(" + cur_astnodename + ")";
                    }
                    if (loc_t == LocMem) {
                        rc = panda_virtual_memory_read(cpu, cur_base_addr, (uint8_t *)&cur_base_addr, sizeof(cur_base_addr));
                        if (rc == -1) {
                            dprintf("Could not dereference pointer so done tainting\n");
                            return;
                        }
                    }
                    else if (loc_t == LocReg) {
                        if (cur_base_addr < CPU_NB_REGS) {
                            cur_base_addr = env->regs[cur_base_addr];
                            // change location type to memory now
                            loc_t = LocMem;
                        }
                        else {
                            return;
                        }
                    }
                    else {
                        // shouldn't get here
                        dprintf("Unknown location type, aborting...\n");
                        abort();
                    }

                    RefTypeInfo *pty = (RefTypeInfo*) ty;
                    DwarfTypeInfo *next_ty = type_map[ty->fname][ty->cu][pty->ref];
                    if (next_ty == nullptr) { 
                        // Check if the lookup failed
                        dprintf("[dwarf2] Warning: PointerType target type (ref 0x%llx) not found in type_map. Skipping dereference. (Current AST: %s)\n",
                        (unsigned long long) pty->ref, cur_astnodename.c_str());
                        // For now, simply returning to prevent crash is best.
                        return;
                    }
                    ty = next_ty; // Only assign if not null
                    tag = ty->type;
                    if (tag == StructType) {
                        cur_astnodename = "*(" + cur_astnodename + ")";
                    }
                    // either query element as a null terminated char *
                    // or a one element array of the type of whatever
                    // we are pointing to
                    if (0 == strcmp("unsigned char", ty->name.c_str()) ||
                        0 == strcmp("char", ty->name.c_str()) ||
                        0 == strcmp("u_char", ty->name.c_str()) ||
                        0 == strcmp("signed char", ty->name.c_str())) {
                        dprintf("Querying: char-type %s  %s\n", ty->name.c_str(), cur_astnodename.c_str());
                        cb(cpu, cur_base_addr, loc_t, -1, cur_astnodename.c_str());
                        return;
                    }
                    break;
                }
            case ArrayType:
                {
                    cb(cpu, cur_base_addr, loc_t, sizeof(cur_base_addr), cur_astnodename.c_str());
                    if (cur_astnodename.find("&") == 0) {
                        cur_astnodename  = cur_astnodename.substr(1);
                    }
                    else {
                        cur_astnodename = "*(" + cur_astnodename + ")";
                    }
                    dprintf("Querying Array Type: ([]) %s\n", cur_astnodename.c_str());
                    
                    assert(loc_t == LocMem);

                    ArrayInfo *arrty = (ArrayInfo*)ty;
                    target_ulong array_size = 0;
                    for (auto r : arrty->ranges) {
                        DwarfTypeInfo *rty = type_map[arrty->fname][arrty->cu][r];
                        assert (rty->type == ArrayRangeType);
                        if (!array_size)
                            array_size = rty->size;
                        else
                            array_size *= rty->size;
                    }
                    //printf("Querying: ([]) %s\n", cur_astnodename.c_str());
                    DwarfTypeInfo *refty = type_map[arrty->fname][arrty->cu][arrty->ref];
                    target_ulong elem_typesize = die_get_type_size(refty);
                    // array size is 0 than we likely have a 0 length
                    // array which is common at the end of structs to make a
                    // flexible length struct
                    array_size = array_size == 0 ? 1 : array_size;
                    cb(cpu, cur_base_addr, loc_t, array_size*elem_typesize, cur_astnodename.c_str());
                    return;
                }
            // can probably treat it as querying taint on an int
            case EnumType:
                dprintf("Querying: (enum) %s\n", cur_astnodename.c_str());
                cb(cpu, cur_base_addr, loc_t, ty->size, cur_astnodename.c_str());
                return;
            case UnionType: // what to do here? should just treat it like a struct
                dprintf("Querying: (union) %s\n", cur_astnodename.c_str());
                return;
            case SubroutineType: // what to do here? just going to default, and continuing to enum die
                dprintf("Querying: (fn) %s\n", cur_astnodename.c_str());
                cb(cpu, cur_base_addr, loc_t, sizeof(cur_base_addr), cur_astnodename.c_str());
                return;
            //case DW_TAG_ptr_to_member_type: // what to do here?
            //    break;
            //// continue enumerating type to get actual type
            //case DW_TAG_typedef:
            //case DW_TAG_restrict_type:
            //// just "skip" these types by continuing to descend type tree
            //case DW_TAG_volatile_type:
            //case DW_TAG_const_type:
            //case DW_TAG_imported_declaration:
            //case DW_TAG_unspecified_parameters:
            //case DW_TAG_constant:
            case SugarType:
                ty = type_map[ty->fname][ty->cu][((RefTypeInfo*)ty)->ref];
                tag = ty->type;
                break;
            default: // we may want to do something different for the default case
                printf("Got unknown DW_TAG: 0x%x\n", tag);
                exit(1);
        }
    }
    return;
}

const char * dwarf2_type_to_string(DwarfVarType *var_ty) {
    std::string argname;
    DwarfTypeInfo *ty = var_ty->type;
    std::string type_name = var_ty->nodename;
    while (ty->type == PointerType ||
           ty->type == SugarType ||
           ty->type == EnumType ||
           ty->type == SubroutineType ||
           ty->type == ArrayType) {
        switch (ty->type) {
            case PointerType: // increment derefs
                type_name = "*" + type_name;
                ty = type_map[ty->fname][ty->cu][((RefTypeInfo*)ty)->ref];
                break;
            case ArrayType:
                type_name += "[]";
                return strdup(type_name.c_str());
            case EnumType:
                type_name += "enum";
                return strdup(type_name.c_str());
            case SubroutineType:
                type_name += "func_pointer ";
                return strdup(type_name.c_str());
            //case DW_TAG_volatile_type:
            //    type_name += "volatile";
            //    break;
            //case DW_TAG_const_type:
            //    type_name += "const ";
            //    break;
            //// just "skip" these types by continuing to descend type tree
            //case DW_TAG_typedef: // continue enumerating type to get actual type
            //case DW_TAG_restrict_type:
            //case DW_TAG_ptr_to_member_type: // what to do here?
            //case DW_TAG_imported_declaration:
            //case DW_TAG_unspecified_parameters:
            //case DW_TAG_constant:
            case SugarType:
                ty = type_map[ty->fname][ty->cu][((RefTypeInfo*)ty)->ref];
                break;
            default: // we may want to do something different for the default case
                printf("Got unknown DW_TAG: 0x%x\n", ty->type);
                exit(1);
        }
    }
    return strdup(type_name.c_str());
}

// called by 'load_debug_info', read dwarf2 json files and populate line_range_list
void load_func_info(const char *dbg_prefix,
        const char *basename,  uint64_t base_address, bool needs_reloc) {
    target_ulong lowpc = 0, highpc = 0;

    std::string funcinfo(std::string(dbg_prefix)+ "_funcinfo.json");
    std::ifstream fs(funcinfo);
    Json::Reader reader;
    Json::Value root;
    reader.parse(fs, root);

    for (Json::Value::const_iterator it = root.begin(); it != root.end(); it++) {
        Json::Value cu = it.key();

        for (Json::Value::const_iterator f = it->begin(); f != it->end(); f++) {
            lowpc = (*f)["scope"]["lowpc"].asUInt64();
            highpc = (*f)["scope"]["highpc"].asUInt64();
            std::string die_name = (*f)["name"].asString();

            if (needs_reloc) {
                lowpc += base_address;
                highpc += base_address;
            }
            //functions[std::string(basename)+"!"+die_name] = std::make_pair(lowpc, highpc);
            auto lineToFuncAddress = [lowpc, highpc](LineRange &x) {
                // if a line range (we just need to check its lowpc) fits between range of a function
                // we update the LineRange to reflect that the line is in the current function
                if (x.lowpc < highpc && x.lowpc >= lowpc) {
                    x.function_addr = lowpc;
                }
            };
            auto lineIsFunctionDef = [lowpc](LineRange &x) {
                return x.lowpc == lowpc;
            };
            auto funct_line_it = std::find_if(line_range_list.begin(), line_range_list.end(), lineIsFunctionDef);

            if (funct_line_it != line_range_list.end()) {
                fn_start_line_range_list.push_back(*funct_line_it);
                // add the LineRange information for the function to fn_name_to_line_info for later use
                // when resolving dwarf information for .plt functions
                // NOTE: this assumes that all function names are unique.

                fn_name_to_line_info.insert(std::make_pair(die_name,
                            LineRange(lowpc,
                                highpc,
                                funct_line_it->line_number,
                                funct_line_it->filename,
                                lowpc,
                                funct_line_it->line_off)));

                // now check if current function we are processing is in dynl_functions if so
                // point the dynl_function to this function's line number, filename, and line_off
                for (auto lib_name : processed_libs) {
                    if (dynl_functions.find(lib_name + ":plt!" + die_name) != dynl_functions.end()) {
                        dprintf("[dwarf2] Trying to match function to %s\n",(lib_name + ":plt!" + die_name).c_str());
                        target_ulong plt_addr = dynl_functions[lib_name + ":plt!" + die_name];
                        dprintf("[dwarf2] Found it at 0x%lx, adding to line_range_list\n", (unsigned long) plt_addr);
                        dprintf("[dwarf2] found a plt function defintion for %s\n", basename);
                        line_range_list.push_back(LineRange(plt_addr,
                                                            plt_addr,
                                                            funct_line_it->line_number,
                                                            funct_line_it->filename,
                                                            lowpc,
                                                            funct_line_it->line_off));

                    }
                }
            } else {
                printf("[dwarf2] Could not find start of function [%s] in line number table something went wrong\n", die_name.c_str());
            }

            // this is if we want the start of the function to be one PAST the line that represents start of function
            // in order to skip past function prologue
            //if (funct_line_it != line_range_list.end()) {
            //    ++funct_line_it;
            //    fn_start_line_range_list.push_back(*funct_line_it);
            //}
            std::for_each(line_range_list.begin(), line_range_list.end(), lineToFuncAddress);
            funcaddrs[lowpc] = std::string(basename) + "!" + die_name;
            // now add functions frame pointer locaiton list funct_to_framepointers mapping
            funct_to_framepointers[lowpc] = (*f)["framebase"];

            std::vector<VarInfo> var_list;
            for (Json::Value::const_iterator v = (*f)["varlist"].begin(); v!=(*f)["varlist"].end(); v++) {
                target_ulong cu = (*v)["cu_offset"].asUInt64();
                target_ulong vlow = (*v)["scope"]["lowpc"].asUInt64();
                target_ulong vhigh = (*v)["scope"]["highpc"].asUInt64();
                if (needs_reloc) {
                    vlow += base_address;
                    vhigh += base_address;
                }
                var_list.push_back(VarInfo(cu, (*v)["type"].asUInt64(), (*v)["name"].asString(),
                            vlow, vhigh, (*v)["loc_op"], (*v)["decl_lno"].asUInt64(), basename));
            }
            // Load information about arguments and local variables
            //printf("Loading arguments and variables for %s\n", die_name);
            funcvars[lowpc] = var_list;
            //printf(" %s #variables: %lu\n", funcaddrs[lowpc].c_str(), var_list.size());
        }
    }
}
std::map<std::string, DwarfType> TypeHelper = {
    {"StructType", StructType},
    {"BaseType", BaseType},
    {"SugarType", SugarType},
    {"PointerType", PointerType},
    {"ArrayType", ArrayType},
    {"ArrayRangeType", ArrayRangeType},
    {"EnumType", EnumType},
    {"SubroutineType", SubroutineType},
    {"UnionType", UnionType},
};

// called by 'load_debug_info', read dwarf2 json files and populate line_range_list
void load_type_info(const char *dbg_prefix, const char *basename, uint64_t base_address, bool needs_reloc) {
    std::string typeinfo(std::string(dbg_prefix)+ "_typeinfo.json");
    std::ifstream fs(typeinfo);
    Json::Reader reader;
    Json::Value root;
    reader.parse(fs, root);

    for (Json::Value::const_iterator it = root.begin(); it != root.end(); it++) {
        target_ulong cu = std::stoul(it.key().asString());
        for (Json::Value::const_iterator ty = it->begin(); ty != it->end(); ty++) {
            target_ulong off = std::stoul(ty.key().asString());
            DwarfType tag = TypeHelper[(*ty)["tag"].asString()];
            switch (tag) {
            case StructType:
            case UnionType:
            {
                AggregateTypeInfo *ti = new AggregateTypeInfo(tag, (*ty)["name"].asString(), (*ty)["size"].asUInt64(), basename, cu);
                for (Json::Value::const_iterator c = (*ty)["children"].begin(); c != (*ty)["children"].end(); c++) {
                    target_ulong memoff = std::stoul(c.key().asString());
                    std::string memname = (*c)[0].asString();
                    target_ulong memtype = (*c)[1].asUInt64();
                    ti->children[memoff] = {memname, memtype};
                }
                type_map[basename][cu][off] = ti;
                break;
            }
            case BaseType:
            case EnumType:
            {
                type_map[basename][cu][off] = new DwarfTypeInfo(
                        tag, (*ty)["name"].asString(), (*ty)["size"].asUInt64(), basename, cu);
                break;
            }
            case SubroutineType:
            {
                type_map[basename][cu][off] = new DwarfTypeInfo(
                        tag, (*ty)["name"].asString(), sizeof(target_ulong), basename, cu);
                break;
            }
            case SugarType:
            case PointerType:
            {
                if (debug) {
                    std::cout << (*ty) <<"\n";
                }
                type_map[basename][cu][off] = new RefTypeInfo(
                        tag, (*ty)["name"].asString(), sizeof(target_ulong),
                        (*ty)["ref"].asUInt64(), basename, cu);
                break;
            }
            case ArrayRangeType:
            {
                type_map[basename][cu][off] = new RefTypeInfo(
                        tag, (*ty)["name"].asString(), (*ty)["size"].asUInt64(),
                        (*ty)["ref"].asUInt64(), basename, cu);
                break;
            }
            case ArrayType:
            {
                ArrayInfo *ai = new ArrayInfo(tag, (*ty)["name"].asString(), (*ty)["ref"].asUInt64(), basename, cu);
                for (Json::Value::const_iterator r = (*ty)["range"].begin(); r!=(*ty)["range"].end(); r++) {
                    ai->ranges.push_back(r->asUInt64());
                }
                type_map[basename][cu][off] = ai;
            }
            default:
                    break;
            }
        }
    }
}

// called by 'load_debug_info', read dwarf2 json files and populate line_range_list
void load_glob_vars(const char *dbg_prefix, const char *basename, uint64_t base_address, bool needs_reloc) {
    std::string globvars(std::string(dbg_prefix)+ "_globvar.json");
    std::ifstream fs(globvars);
    Json::Reader reader;
    Json::Value root;
    reader.parse(fs, root);

    for (Json::Value::const_iterator it = root.begin(); it != root.end(); it++) {
        for (Json::Value::const_iterator v = it->begin(); v != it->end(); v++) {
            target_ulong cu = (*v)["cu_offset"].asUInt64();
            target_ulong lowpc = (*v)["scope"]["lowpc"].asUInt64();
            target_ulong highpc = (*v)["scope"]["highpc"].asUInt64();

            if (needs_reloc) {
                lowpc += base_address;
                highpc += base_address;
            }

            global_var_list.push_back(VarInfo(cu, (*v)["type"].asUInt64(), (*v)["name"].asString(),
                            lowpc, highpc, (*v)["loc_op"], (*v)["decl_lno"].asUInt64(), basename));
        }
    }
}

// called by 'load_debug_info', read dwarf2 json files and populate line_range_list
bool populate_line_range_list(const char *dbg_prefix, const char *basename, uint64_t base_address, bool needs_reloc) {
    std::string lineinfo(std::string(dbg_prefix)+ "_lineinfo.json");
    std::ifstream fs(lineinfo);
    Json::Reader reader;
    Json::Value root;
    reader.parse(fs, root);
   
    for (Json::Value::const_iterator it = root.begin(); it != root.end(); it++) {
        std::string srcfn = it.key().asString();
        assert (it->isArray());
        for (int i = 0; i < it->size(); i++) {
            Json::Value lr = (*it)[i];
            if (needs_reloc) {
                LineRange r = LineRange(base_address+lr["lowpc"].asUInt64(),
                        base_address+lr["highpc"].asUInt64(),
                        lr["lno"].asUInt(), srcfn, lr["func"].asUInt64(), lr["col"].asUInt());
                line_range_list.push_back(r);
            } else {
                LineRange r = LineRange(lr["lowpc"].asUInt64(), lr["highpc"].asUInt64(),
                        lr["lno"].asUInt(), srcfn, lr["func"].asUInt64(), lr["col"].asUInt());
                line_range_list.push_back(r);
            }

            if (debug) {
                std::cout << lr << "\n";
            }
        }
    }
    return true;
}

// Load all function and global variable info
bool load_debug_info(const char *dbg_prefix, const char *basename, uint64_t base_address, bool needs_reloc) {
    populate_line_range_list(dbg_prefix, basename, base_address, needs_reloc);
    printf("line_range_list.size() = %d\n", (int) line_range_list.size());

    load_func_info(dbg_prefix, basename, base_address, needs_reloc);
    load_glob_vars(dbg_prefix, basename, base_address, needs_reloc);
    load_type_info(dbg_prefix, basename, base_address, needs_reloc);
    
    // sort the line number ranges
    std::sort(fn_start_line_range_list.begin(), fn_start_line_range_list.end(), sortRange);
    std::sort(line_range_list.begin(), line_range_list.end(), sortRange);
    printf("Successfully loaded debug symbols for %s\n", basename);
    printf("Number of address range to line mappings: %zu num globals: %zu\n",
           (size_t)line_range_list.size(), (size_t)global_var_list.size());
    return true;
}

// You need this code to run to fill out TaintQueryPri
bool read_debug_info(const char* dbg_prefix, const char *basename, uint64_t base_address, bool needs_reloc) {
    if (needs_reloc) {
        dprintf("[Dwarf2] Relocating all line ranges and global variables");
    }
    else {
        dprintf("[Dwarf2] NOT relocating all line ranges and global variables");
    }

    printf("read_debug_info %s\n", dbg_prefix);
    if (!load_debug_info(dbg_prefix, basename, base_address, needs_reloc)) {
        fprintf(stderr, "Failed DWARF loading\n");
        return false;
    }
    return true;
}

std::set<target_ulong> monitored_asid;
unsigned num_libs_known = 0;

bool correct_asid(CPUState *cpu) {
    if (monitored_asid.size() == 0) {
        return false;
    }
    return (monitored_asid.count(panda_current_asid(cpu)) != 0);
}

bool looking_for_libc = false;
const char *libc_host_path = NULL;
std::string libc_name;

// This function is called from the 'loaded' plugin
void on_library_load(CPUState *cpu, target_ulong pc, char *guest_lib_name, target_ulong base_addr, target_ulong size) {
    printf("on_library_load guest_lib_name=%s\n", guest_lib_name);
    if (!correct_asid(cpu)) {
        dprintf("current_asid=" TARGET_FMT_lx " is not monitored\n", panda_current_asid(cpu));
        return;
    }
    active_libs.push_back(Lib(guest_lib_name, base_addr, base_addr + size));
    std::string lib = std::string(guest_lib_name);
    std::size_t found = lib.find(guest_debug_path);
    if (found == std::string::npos) {
        char *lib_name = strdup((host_mount_path + lib).c_str());
        dprintf("access(%s, F_OK): %x\n", lib_name, access(lib_name, F_OK));
        if (access(lib_name, F_OK) == -1) {
            fprintf(stderr, "Couldn't open %s; will not load symbols for it.\n", lib_name);
            return;
        }
        if (looking_for_libc && lib.find(libc_name) != std::string::npos) {
            lib_name = strdup(libc_host_path);
            dprintf("actually loading lib_name = %s\n", lib_name);
            bool needs_reloc = true; // elf_base != base_addr;
            read_debug_info(lib_name, basename(lib_name), base_addr, needs_reloc);
            return;
        }
        elf_get_baseaddr(lib_name, basename(lib_name), base_addr);
        return;
    }
    std::string host_lib = lib.substr(0, found) + host_debug_path + lib.substr(found+strlen(guest_debug_path));
    char *lib_name = strdup(host_lib.c_str());
    printf("Trying to load symbols for %s at 0x" TARGET_FMT_lx ".\n", lib_name, base_addr);
    printf("access(%s, F_OK): %x\n", lib_name, access(lib_name, F_OK));
    if (access(lib_name, F_OK) == -1) {
        fprintf(stderr, "Couldn't open %s; will not load symbols for it.\n", lib_name);
        return;
    }
    uint64_t elf_base = elf_get_baseaddr(lib_name, basename(lib_name), base_addr);
    printf("Value of elf base address: 0x%lx\n", (unsigned long) elf_base);
    bool needs_reloc = elf_base != base_addr;
    if (!read_debug_info(lib_name, basename(lib_name), base_addr, needs_reloc)) {
        fprintf(stderr, "Couldn't load symbols from %s.\n", lib_name);
        return;
    }
    return;
}

// This function is used to get debug info of the main executable
bool main_exec_initialized = false;
bool ensure_main_exec_initialized(CPUState *cpu) {
    char fname[260] = {};
    OsiProc * p = get_current_process(cpu);
    printf("[ensure_main_exec_initialized] looking at libraries from the following program %s\n", p->name);
    if (strncmp(p->name, proc_to_monitor, strlen(p->name)) != 0) {
        dprintf("[ensure_main_exec_initialized] Incorrect process to get mappings for: %s\n", p->name);
        return false;
    }
    GArray * libs = get_mappings(cpu, p);
    free_osiproc(p);
    if (!libs) {
        dprintf("[ensure_main_exec_initialized] Couldn't get mappings for %s.\n", p->name);
        return false;
    }

    for (unsigned i = 0; i < libs->len; i++) {
        OsiModule *m = &g_array_index(libs, OsiModule, i);
        if (!m->file) {
            continue;
        }
        if (!m->name) {
            continue;
        }
        std::string lib = std::string(m->file);
        dprintf("[ensure_main_exec_initialized] looking at file %s\n", m->file);
        
        if (strncmp(m->name, proc_to_monitor, strlen(m->name)) != 0) {
            continue;
        }
        strcpy(fname, bin_path.c_str());
        dprintf("[ensure_main_exec_initialized] Trying to load symbols for %s at 0x" TARGET_FMT_lx ".\n", fname, m->base);
        dprintf("[ensure_main_exec_initialized] access(%s, F_OK): %x\n", fname, access(fname, F_OK));
        if (access(fname, F_OK) == -1) {
            fprintf(stderr, "Couldn't open %s; will not load symbols for it.\n", fname);
            continue;
        }
        active_libs.push_back(Lib(fname, m->base, m->base + m->size));
        uint64_t elf_base = elf_get_baseaddr(fname, m->name, m->base);
        dprintf("[ensure_main_exec_initialized] Value of elf base address: 0x%lx\n", (unsigned long) elf_base);
        bool needs_reloc = elf_base != m->base;
        if (!read_debug_info(fname, m->name, m->base, needs_reloc)) {
            fprintf(stderr, "[ensure_main_exec_initialized] Couldn't load symbols from %s.\n", fname);
            continue;
        }
        printf("[ensure_main_exec_initialized] SUCCESS\n");
        return true;
    }
    return false;
}

target_ulong dwarf2_get_cur_fp(CPUState *cpu, target_ulong pc) {
    if (funct_to_framepointers.find(cur_function) == funct_to_framepointers.end()) {
        printf("funct_to_framepointers: could not find fp information for current function\n");
        return -1;
    }
    Json::Value ops = funct_to_framepointers[cur_function];
    if (!ops.size()) {
        printf("loc_cnt: Could not properly determine fp\n");
        return -1;
    }
    CPUArchState *env = (CPUArchState*) cpu->env_ptr;
    target_ulong fp_loc;
    LocType loc_type = execute_stack_op(cpu,pc, ops, 0, &fp_loc);
    switch (loc_type) {
        case LocReg:
            return env->regs[fp_loc];
        case LocMem:
            return fp_loc;
        case LocConst:
        case LocErr:
            printf("loc_type: Could not properly determine fp\n");
            return -1;
    }
    //printf("Found fp at 0x%x\n", fp_loc);
    printf("Not in range: Could not properly determine fp for pc @ 0x" TARGET_FMT_lx "\n", pc);
    return -1;
}

bool dwarf_in_target_code(CPUState *cpu, target_ulong pc) {
    if (!correct_asid(cpu)) {
        return false;
    }
    std::vector<LineRange>::iterator it = std::lower_bound(line_range_list.begin(), line_range_list.end(), pc, CompareRangeAndPC());
    return (it != line_range_list.end() && pc >= it->lowpc);
}

void dwarf_log_callsite(CPUState *cpu, const char *file_callee, const char *fn_callee, uint64_t lno_callee, bool isCall) {
    target_ulong ra = 0;

    int num_received = get_callers(&ra, 1, cpu);
    if (num_received < 1) {
        printf("Error No dwarf information. Could not get callers from callstack plugin\n");
    }

    ra -= 5; // subtract 5 to get address of call instead of return address
    std::vector<LineRange>::iterator it = std::lower_bound(line_range_list.begin(), line_range_list.end(), ra, CompareRangeAndPC());
    if (it == line_range_list.end() || ra < it->lowpc) {
        //printf("No DWARF information for callsite 0x%x for current function.\n", ra);
        //printf("Callsite must be in an external library we do not have DWARF information for.\n");
        return;
    }
    target_ulong call_site_fn = it->function_addr;
    std::string file_name = it->filename;
    unsigned long lno = it->line_number;
    std::string funct_name = funcaddrs[call_site_fn];

    //void pri_dwarf_plog(char *file_callee, char *fn_callee, uint64_t lno_callee, char *file_caller, uint64_t lno_caller, bool isCall)
    pri_dwarf_plog(file_callee, fn_callee, lno_callee, file_name.c_str(), lno, isCall);
    /*
    if (isCall) {
    }
        printf(" CALL: [%s] [0x%llx]-%s(), ln: %4lld, pc @ 0x%x\n",file_name.c_str(),call_site_fn, funct_name.c_str(),lno,ra);
    else {
        printf(" RET: [%s] [0x%llx]-%s(), ln: %4lld, pc @ 0x%x\n",file_name.c_str(),call_site_fn, funct_name.c_str(),lno,ra);
    }
    */
    return;
}

void on_call(CPUState *cpu, target_ulong pc) {
    if (!correct_asid(cpu)) {
        return;
    }
    std::vector<LineRange>::iterator it = std::lower_bound(line_range_list.begin(), line_range_list.end(), pc, CompareRangeAndPC());
    // std::size_t remaining_size = std::distance(it, line_range_list.end());
    // dprintf("[on_call] Size of line_range_list: %zu\n", line_range_list.size());
    // dprintf("[on_call] Remaining size from iterator to end: %zu\n", remaining_size);

    if (it == line_range_list.end() || pc < it->lowpc) {
        std::map<target_ulong, std::string>::iterator it_dyn = addr_to_dynl_function.find(pc);
        if (it_dyn != addr_to_dynl_function.end()) {
            // dprintf("CALL: Found line info for 0x" TARGET_FMT_lx "\n", pc);
            pri_runcb_on_fn_start(cpu, pc, NULL, it_dyn->second.c_str());
        }
        else {
            // dprintf("CALL: Could not find line info for 0x" TARGET_FMT_lx "\n", pc);
        }
        return;
    }
    cur_function = it->function_addr;
    std::string file_name = it->filename;
    std::string funct_name = funcaddrs[cur_function];
    cur_line = it->line_number;
    if (it->lowpc == it->highpc) {
        //printf("Calling %s through .plt\n",file_name.c_str());
    }
    //printf("CALL: [%s] [0x%llx]-%s(), ln: %4lld, pc @ 0x%x\n",file_name.c_str(),cur_function, funct_name.c_str(),cur_line,pc);
    if (logCallSites) {
        dwarf_log_callsite(cpu, file_name.c_str(), funct_name.c_str(), cur_line, true);
    }
    pri_runcb_on_fn_start(cpu, pc, file_name.c_str(), funct_name.c_str());

    /*
    if (funcaddrs.find(pc) != funcaddrs.end()) {
        // count consecutive occurences of function calls and only record the last one and its count
        if (pc == prev_pc) {
            prev_pc_count += 1;
            return;
        }
        else if (prev_pc_count > 0) {
            //printf("%s(%s) [Executed %d times]\n", funcaddrs[prev_pc].c_str(), funcparams[prev_pc].c_str(), prev_pc_count);
            prev_pc_count = 0;
        }
        //printf("%s(%s)\n", funcaddrs[pc].c_str(), funcparams[pc].c_str());
        prev_pc = pc;
        if (funcaddrs[pc].find(":plt!") == std::string::npos) {
            // do something
        }
    }
    */
    // called function is in a dynamic library AND function information
    // hasn't been loaded into funcaddrs and funcparams yet
    //else {
    //    printf("Unknown function at: %x\n", prev_pc);
    //}
}

// pc_func - of the function we are returning from
void on_ret(CPUState *cpu, target_ulong pc_func) {
    if (!correct_asid(cpu)) {
        return;
    }
    std::vector<LineRange>::iterator it = std::lower_bound(line_range_list.begin(), line_range_list.end(), pc_func, CompareRangeAndPC());    
    // Calculate the size of the remaining range from the iterator to the end
    // std::size_t remaining_size = std::distance(it, line_range_list.end());
    // dprintf("[on_ret] Size of line_range_list: %zu\n", line_range_list.size());
    // dprintf("[on_ret] Remaining size from iterator to end: %zu\n", remaining_size);

    if (it == line_range_list.end() || pc_func < it->lowpc) {
        std::map<target_ulong, std::string>::iterator it_dyn = addr_to_dynl_function.find(pc_func);
        if (it_dyn != addr_to_dynl_function.end()) {
            // dprintf("RET: Found line info for 0x" TARGET_FMT_lx "\n", pc_func);
            pri_runcb_on_fn_return(cpu, pc_func, NULL, it_dyn->second.c_str());
        }
        else {
            // dprintf("RET: Could not find line info for 0x" TARGET_FMT_lx "\n", pc_func);
        }
        return;
    }
    cur_function = it->function_addr;
    std::string file_name = it->filename;
    std::string funct_name = funcaddrs[cur_function];
    cur_line = it->line_number;
    //printf("RET: [%s] [0x%llx]-%s(), ln: %4lld, pc @ 0x%x\n",file_name.c_str(),cur_function, funct_name.c_str(),cur_line,pc_func)
    if (logCallSites) {
        dwarf_log_callsite(cpu, file_name.c_str(), funct_name.c_str(), cur_line, false);
    }
    pri_runcb_on_fn_return(cpu, pc_func, file_name.c_str(), funct_name.c_str());
}

void __livevar_iter(CPUState *cpu, target_ulong pc,
        std::vector<VarInfo> vars, liveVarCB f,
        void *args, target_ulong fp) {
    //printf("size of vars: %ld\n", vars.size());
    for (auto it : vars) {
        std::string var_name = it.var_name;
        DwarfVarType var_type {type_map[it.fname][it.cu][it.var_type], it.dec_line, var_name};
        target_ulong var_loc;
        LocType loc = execute_stack_op(cpu,pc, it.loc_ops, fp, &var_loc);
        if (debug) {
            switch (loc) {
                case LocReg:
                    dprintf(" [livevar_iter] VAR %s in REG " TARGET_FMT_lu "\n", var_name.c_str(), var_loc);
                    break;
                case LocMem:
                    dprintf(" [livevar_iter] VAR %s in MEM 0x" TARGET_FMT_lx "\n", var_name.c_str(), var_loc);
                    break;
                case LocConst:
                    dprintf(" [livevar_iter] VAR %s CONST VAL " TARGET_FMT_lx "\n", var_name.c_str(), var_loc);
                    break;
                case LocErr:
                    dprintf(" [livevar_iter] VAR %s - Can\'t handle location information\n", var_name.c_str());
                    break;
            }
        }
        f((void *)&var_type, var_name.c_str(),loc, var_loc, args);
    }
    return;
}

// returns 1 if successful find, 0 ow
// will assign found variable to ret_var
int livevar_find(CPUState *cpu, target_ulong pc,
        std::vector<VarInfo> vars,
        liveVarPred pred, void *args, VarInfo &ret_var) {

    target_ulong fp = dwarf2_get_cur_fp(cpu, pc);
    if (fp == (target_ulong) -1) {
        printf("Error: was not able to get the Frame Pointer for the function %s at @ 0x" TARGET_FMT_lx "\n", funcaddrs[cur_function].c_str(), pc);
        return 0;
    }
    for (std::vector<VarInfo>::iterator it = vars.begin(); it != vars.end(); ++it) {
        target_ulong var_loc;
        LocType loc = execute_stack_op(cpu, pc, it->loc_ops, fp, &var_loc);
        if (pred((void*) &it->var_type, it->var_name.c_str(), loc, var_loc, args)) {
            ret_var.cu = it->cu;
            ret_var.var_type = it->var_type;
            ret_var.var_name = it->var_name;
            ret_var.loc_ops = it->loc_ops;
            return 1;
        }
    }
    return 0;
}

/********************************************************************
 * end PPPs
******************************************************************** */
int compare_address(void *var_ty, const char *var_nm, LocType loc_t, target_ulong loc, void *query_address) {
    switch (loc_t) {
        case LocReg:
            break;
        case LocMem:
            return (loc == (*(target_ulong *) query_address));
        case LocConst:
            break;
        case LocErr:
            break;
    }
    return 0;
}
void dwarf_get_vma_symbol (CPUState *cpu, target_ulong pc, target_ulong vma, char ** symbol_name) {
    if (!correct_asid(cpu)) {
        *symbol_name = NULL;
        return;
    }
    target_ulong fn_address;

    std::vector<LineRange>::iterator it = std::lower_bound(line_range_list.begin(), line_range_list.end(), pc, CompareRangeAndPC());
    if (it == line_range_list.end() || pc < it->lowpc) {
        *symbol_name = NULL;
        return;
    }
    fn_address = it->function_addr;

    VarInfo ret_var;
    if (livevar_find(cpu, pc, funcvars[fn_address], compare_address, (void *) &vma, ret_var)) {
        *symbol_name = (char *)ret_var.var_name.c_str();
        return;
    }
    *symbol_name = NULL;
    return;
}

// This is the function called by 'pri_get_pc_source_info' in pri_taint.cpp
void dwarf_get_pc_source_info(CPUState *cpu, target_ulong pc, SrcInfo *info, int *rc) {
    if (!correct_asid(cpu)) {
        dprintf("Not in a correct asid in dwarf_get_pc_source_info\n");
        *rc = -1;
        return;
    }
    
    // Print the size of line_range_list, 
    // if empty, I suspect because the DWARF information is not loaded
    // this gets populated in 'populate_line_range_list', which is called by 'load_debug_info'
    std::vector<LineRange>::iterator it = std::lower_bound(line_range_list.begin(), line_range_list.end(), pc, CompareRangeAndPC());
    // std::size_t remaining_size = std::distance(it, line_range_list.end());
    // dprintf("[dwarf_get_pc_source_info] Size of line_range_list: %zu\n", line_range_list.size());
    // dprintf("[dwarf_get_pc_source_info] Remaining size from iterator to end: %zu\n", remaining_size);

    if (it == line_range_list.end() || pc < it->lowpc) {
        std::map<target_ulong, std::string>::iterator it_dyn = addr_to_dynl_function.find(pc);
        if (it_dyn != addr_to_dynl_function.end()) {
            dprintf("In a a plt function\n");
            info->filename = NULL;
            info->line_number = 0;
            info->funct_name = it_dyn->second.c_str();
            *rc = 1;
        }
        else {
            dprintf("Error found in plt function\n");
            *rc = -1;
        }
        return;
    }

    if (it->lowpc == it->highpc) {
        dprintf("In a a plt function\n");
        *rc = 1;
        return;
    }
    // we are in dwarf-land, so populate info struct
    target_ulong call_site_fn = it->function_addr;
    info->filename = it->filename.c_str();
    info->line_number = it->line_number;
    std::string funct_name = funcaddrs[call_site_fn];
    info->funct_name = funct_name.c_str();
    *rc = 0;
    return;
}
void dwarf_all_livevar_iter(CPUState *cpu, target_ulong pc, liveVarCB f, void *args) {
    if (inExecutableSource) {
        target_ulong fp = dwarf2_get_cur_fp(cpu, pc);
        if (fp == (target_ulong) -1) {
            printf("Error: was not able to get the Frame Pointer for the function %s at @ 0x" TARGET_FMT_lx "\n",
                    funcaddrs[cur_function].c_str(), pc);
            return;
        }
        __livevar_iter(cpu, pc, funcvars[cur_function], f, args, fp);
    }
    else {
        // dprintf("[dwarf_all_livevar_iter] is NOT in executable source!\n");
    }

    // iterating through global vars does not require a frame pointer
    __livevar_iter(cpu, pc, global_var_list, f, args, 0);
}
void dwarf_funct_livevar_iter(CPUState *cpu, target_ulong pc, liveVarCB f, void *args) {
    dprintf("iterating through live vars\n");
    if (inExecutableSource) {
        target_ulong fp = dwarf2_get_cur_fp(cpu, pc);
        if (fp == (target_ulong) -1) {
            printf("Error: was not able to get the Frame Pointer for the function %s at @ 0x" TARGET_FMT_lx "\n",
                    funcaddrs[cur_function].c_str(), pc);
            return;
        }
        __livevar_iter(cpu, pc, funcvars[cur_function], f, args, fp);
    }
    else {
        // dprintf("[dwarf_funct_livevar_iter] is NOT in executable source!\n");
    }
}
void dwarf_global_livevar_iter(CPUState *cpu, target_ulong pc, liveVarCB f, void *args) {
    // iterating through global vars does not require a frame pointer
    __livevar_iter(cpu, pc, global_var_list, f, args, 0);
}

bool translate_callback_dwarf(CPUState *cpu, target_ulong pc) {
    if (!correct_asid(cpu)) {
        return false;
    }
    std::vector<LineRange>::iterator it2 = std::lower_bound(line_range_list.begin(), line_range_list.end(), pc, CompareRangeAndPC());
    // after the call to lower_bound the `pc` should be between it2->lowpc and it2->highpc
    // if it2 == line_range_list.end() we know we definitely didn't find out pc in our line_range_list
    if (it2 == line_range_list.end() || pc < it2->lowpc) {
        return false;
    }
    return true;
    /*
    // This is just the linear search to confirm binary search (lower_bound) is
    // working correctly
    auto addressInRange = [pc](LineRange lr) {
        return pc >= lr.lowpc && pc < lr.highpc;
    };
    auto it = find_if(line_range_list.begin(), line_range_list.end(), addressInRange);
    if (it == line_range_list.end())
        return false;
    */
}

int exec_callback_dwarf(CPUState *cpu, target_ulong pc) {
    dprintf("[dwarf2] exec_callback_dwarf is called\n");
    inExecutableSource = false;
    if (!correct_asid(cpu)) {
        return 0;
    }
    std::vector<LineRange>::iterator it2 = std::lower_bound(line_range_list.begin(), line_range_list.end(), pc, CompareRangeAndPC());
    if (it2 == line_range_list.end() || pc < it2->lowpc) {
        return 0;
    }
    inExecutableSource = true;
    dprintf("[dwarf2] exec_callback_dwarf has set inExecutable Source to true\n");
    if (it2->lowpc == it2->highpc) {
        dprintf("[dwarf2] exec_callback_dwarf has set inExecutable Source to false\n");
        inExecutableSource = false;
    }
    cur_function = it2->function_addr;
    std::string file_name = it2->filename;
    std::string funct_name = funcaddrs[cur_function];
    cur_line = it2->line_number;

    //printf("[%s] [0x%llx]-%s(), ln: %4lld, pc @ 0x%x\n",file_name.c_str(),cur_function, funct_name.c_str(),cur_line,pc);
    if (funcaddrs.find(cur_function) == funcaddrs.end()) {
        return 0;
    }    
    if (cur_function == 0) {
        return 0;
    }
    //printf("[%s] [0x%llx]-%s(), ln: %4lld, pc @ 0x%x\n",file_name.c_str(),cur_function, funct_name.c_str(),cur_line,pc);
    //__livevar_iter(env, pc, funcvars[cur_function], push_var_if_live);
    //__livevar_iter(env, pc, global_var_list, push_var_if_live);
    //__livevar_iter(env, pc, global_var_list, print_var_if_live);
    if (cur_line != prev_line) {
        //printf("[%s] %s(), ln: %4lld, pc @ 0x%x\n",file_name.c_str(), funct_name.c_str(),cur_line,pc);
        pri_runcb_on_after_line_change (cpu, pc, prev_file_name.c_str(), prev_funct_name.c_str(), prev_line);
        pri_runcb_on_before_line_change(cpu, pc, file_name.c_str(), funct_name.c_str(), cur_line);
        PPP_RUN_CB(on_dwarf2_line_change, cpu, pc, file_name.c_str(), funct_name.c_str(), cur_line);

        // reset previous line information
        prev_file_name = file_name;
        prev_funct_name = funct_name;
        prev_line_pc = pc;
        prev_function = cur_function;
        prev_line = cur_line;
    }
    //if (funcaddrs.find(pc) != funcaddrs.end()) {
    //    on_call(env, pc);
    //}
    return 0;
}
/********************************************************************
 * end PPPs
******************************************************************** */

uint32_t guest_strncpy(CPUState *cpu, char *buf, size_t maxlen, target_ulong guest_addr) {
    buf[0] = 0;
    unsigned i;
    for (i=0; i<maxlen; i++) {
        uint8_t c;
        panda_virtual_memory_rw(cpu, guest_addr+i, &c, 1, 0);
        buf[i] = c;
        if (c == 0) {
            break;
        }
    }
    buf[maxlen - 1] = 0;
    return i;
}

typedef void (* on_proc_change_t)(CPUState *env, target_ulong asid, OsiProc *proc);

void handle_asid_change(CPUState *cpu, target_ulong asid, OsiProc *p) {
    if (!p) { 
        return; 
    }
    if (!p->name) { 
        return; 
    }
    dprintf("p-name: %s proc-to-monitor: %s\n", p->name, proc_to_monitor);
    
    if (strncmp(p->name, proc_to_monitor, strlen(p->name)) == 0) {
        target_ulong current_asid = panda_current_asid(cpu);
        monitored_asid.insert(current_asid);
        dprintf("monitoring asid " TARGET_FMT_lx "\n", current_asid);
    }
}
// XXX: osi_foo is largetly commented out and basically does nothing
// I am keeping it here as a reminder of maybe tracking of a data structure
// that maps asid's to process data (library information, proc name, etc)
// but we don't need that yet, and it's probably better suited in asidstory
// or pri
// XXX
// get current process before each bb execs
// which will probably help us actually know the current process
uint64_t bb_count = 0;
void osi_foo(CPUState *cpu, TranslationBlock *tb) {
    // First attempt to load debug symbols for main process
    bb_count++;
    if ((bb_count % 100) == 0) {
        if (correct_asid(cpu) && !main_exec_initialized) {
            main_exec_initialized = ensure_main_exec_initialized(cpu);
        }
    }

    if (panda_in_kernel(cpu)) {
        OsiProc *p = get_current_process(cpu);
        if (!p) {
            return;
        }
        //some sanity checks on what we think the current process is
        // this means we didnt find current task
        //if (p->taskd == 0) return;
        //// or the name
        //if (p->name == 0) return;
        //// this is just not ok
        //if (((int) p->pid) == -1) return;
        //uint32_t n = strnlen(p->name, 32);
        //// name is one char?
        //if (n<2) return;
        //uint32_t np = 0;
        //for (uint32_t i=0; i<n; i++) {
            //np += (isprint(p->name[i]) != 0);
        //}
        //// name doesnt consist of solely printable characters
        //if (np != n) return;
        target_ulong asid = panda_current_asid(cpu);
        if (running_procs.count(asid) == 0) {
            printf("adding asid=0x%x to running procs.  cmd=[%s]  task=0x%x\n", (unsigned int)  asid, p->name, (unsigned int) p->taskd);
        }
        running_procs[asid] = *p;
        //proc_changed = proc_diff(current_proc, p);
        //if (proc_changed) {
            //if (current_proc != NULL) {
                //free_osiproc(current_proc);
                //current_proc = NULL;
            //}
            //current_proc = copy_osiproc_g(p, current_proc);
            ////printf("proc changed to [%s]\n", current_proc->name);
        //}
        free_osiproc(p);
        // turn this off until next asid change
        //if (current_proc != NULL && proc_changed) {
            //// if we get here, we have a valid proc in current_proc
            //// that is new.  That is, we believe process has changed
            //if (current_libs) {
                //g_array_free(current_libs, true);
            //}
            //current_libs = get_mappings(cpu, current_proc);
            //if (current_libs) {
                //for (unsigned i=0; i<current_libs->len; i++) {
                    //OsiModule *m = &(current_libs->module[i]);
                    //if (tb->pc >= m->base &&
                            //tb->pc < (m->base + m->size)) {
                        //current_lib = m;
                    //}
                //}
            //}
        //}
    }
    return;
}
#endif

bool init_plugin(void *self) {
#if defined(TARGET_I386) || defined(TARGET_ARM)
    panda_arg_list *args_gen = panda_get_args("general");
    const char *asid_s = panda_parse_string_opt(args_gen, "asid", NULL, "asid of the process to follow for pri_trace");
    if (asid_s) {
        target_ulong asid = strtoul(asid_s, NULL, 16);
        monitored_asid.insert(asid); 
        printf("Tracking process by ASID: %lx\n", (uint64_t) asid);
    }
    else {
        printf("No asid provided, tracking all processes\n");
    }
    panda_arg_list *args = panda_get_args("dwarf2");
    debug = panda_parse_bool_opt(args, "debug", "enable debug output");
    guest_debug_path = panda_parse_string_req(args, "g_debugpath", "path to binary/build dir on guest machine");
    host_debug_path = panda_parse_string_req(args, "h_debugpath", "path to binary/build dir on host machine");
    host_mount_path = panda_parse_string_opt(args, "host_mount_path", "dbg", "path to mounted guest file system");
    proc_to_monitor = panda_parse_string_req(args, "proc", "name of process to follow with dwarf info");
    libc_host_path = panda_parse_string_opt(args, "host_libc_path", "None", "path to guest libc on host");
    // this option allows dwarf/elf processing to continue if no 
    // dwarf symbols are including.  presumably only using plt symbols
    // for line range data.  could be useful for tracking calls to functions
    allow_just_plt = panda_parse_bool_opt(args, "allow_just_plt", "allow parsing of elf for dynamic symbol information if dwarf is not available");
    logCallSites = !panda_parse_bool_opt(args, "dont_log_callsites", "Turn off pandalogging of callsites in order to reduce plog output");

    // Only used for on_library_load
    if (0 != strcmp(libc_host_path, "None")) {
        looking_for_libc = true;
        libc_name = std::string(strstr(libc_host_path, "libc"));
        printf("looking for libc. libc_name=[%s]\n", libc_name.c_str());
    }
    // panda plugin plugin includes
    panda_require("callstack_instr");
    panda_require("osi");
    panda_require("loaded");
    panda_require("pri");
    panda_require("asidstory");

    assert(init_callstack_instr_api());
    assert(init_osi_linux_api());
    assert(init_osi_api());
    assert(init_pri_api());

    panda_enable_precise_pc();
    panda_enable_memcb();
    // we may want to change back to using on_call and on_ret CBs
    PPP_REG_CB("callstack_instr", on_call, on_call);
    PPP_REG_CB("callstack_instr", on_ret, on_ret);
    struct stat s;
    if (stat(host_debug_path, &s) != 0) {
        printf("host_debug path does not exist. exiting . . .\n");
        exit(1);
    }
    // host_debug_path is a dir
    // if debug path doesn't point to a file assume debug path points to an install
    // directory on host machine, so add '/bin/' in order to get the main executable
    if (s.st_mode & S_IFDIR) {
        bin_path = std::string(host_debug_path) + "/bin/" + proc_to_monitor;
        if (stat(bin_path.c_str(), &s) != 0) {
            bin_path = std::string(host_debug_path) + "/lib/" + proc_to_monitor;
            if (stat(bin_path.c_str(), &s) != 0) {
                bin_path = std::string(host_debug_path) + "/" + proc_to_monitor;
                if (stat(bin_path.c_str(), &s) != 0) {
                    printf("Can\' find a valid main bin path\n");
                    printf("[WARNING] Skipping processing of main file!!!\n");
                    bin_path = "";
                }
            }
        }
    } else if (s.st_mode & S_IFREG) {
        // if debug path actually points to a file, then make host_debug_path the
        // directory that contains the executable
        bin_path = std::string(host_debug_path);
        // host_debug_path = dirname(strdup(host_debug_path));
        host_debug_path = dirname(strdup(host_debug_path));
    } else {
        printf("Don\'t know what host_debug_path: %s is, but it is not a file or directory\n", host_debug_path);
        exit(1);
    }
    if (bin_path == "") {
        printf("Don\'t know bin path\n");
        exit(1);
    }

    {
        panda_cb pcb_dwarf;
        pcb_dwarf.before_block_exec = osi_foo;
        panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb_dwarf);
        pcb_dwarf.insn_translate = translate_callback_dwarf;
        panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb_dwarf);
        pcb_dwarf.insn_exec = exec_callback_dwarf;
        panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb_dwarf);
    }

    PPP_REG_CB("asidstory", on_proc_change, handle_asid_change);
    PPP_REG_CB("loaded", on_library_load, on_library_load);
    // contracts we fulfill for pri plugin
    PPP_REG_CB("pri", on_get_pc_source_info, dwarf_get_pc_source_info);
    PPP_REG_CB("pri", on_get_vma_symbol, dwarf_get_vma_symbol);
    PPP_REG_CB("pri", on_all_livevar_iter, dwarf_all_livevar_iter);
    PPP_REG_CB("pri", on_funct_livevar_iter, dwarf_funct_livevar_iter);
    PPP_REG_CB("pri", on_global_livevar_iter, dwarf_global_livevar_iter);
    return true;
#else
    printf("Dwarf2 plugin not supported on this architecture\n");
    return false;
#endif
}

void uninit_plugin(void *self) {
#if defined(TARGET_I386) || defined(TARGET_ARM)
    std::sort(active_libs.begin(), active_libs.end());
    std::ofstream outfile(std::string(proc_to_monitor) + ".libs");
    for (const Lib &l : active_libs) {
        printf("library: 0x%lx-0x%lx, %s\n", (uint64_t) l.lowpc, (uint64_t) l.highpc, l.libname.c_str());
        outfile << l << "\n";
    }
    for (auto it : type_map) {
        for (auto iit : it.second) {
            for (auto iiit: iit.second) {
                delete iiit.second;
            }
        }
    }
#endif
}
