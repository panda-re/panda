/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/panda_addr.h"
extern "C" {

#include "config.h"
#include "rr_log.h"
#include "qemu-common.h"
#include "panda_common.h"
#include "cpu.h"
#include "cpu.h"

#include "pandalog.h"
#include "panda_plugin.h"
#include "panda_plugin_plugin.h"
#include "pri_dwarf_util.h"
#include "pri_dwarf.h"
#include "pri_dwarf_types.h"

#include "../pri/pri_types.h"
#include "../pri/pri_ext.h"
#include "../pri/pri.h"

#include "../osi/osi_types.h"
#include "../osi/osi_ext.h"

// this provides the fd resolution magic
#include "../osi_linux/osi_linux_ext.h"

#include "../syscalls2/gen_syscalls_ext_typedefs.h"


#include "../loaded/loaded.h"

bool init_plugin(void *);
void uninit_plugin(void *);
//void on_ret(CPUState *env, target_ulong pc);
//void on_call(CPUState *env, target_ulong pc);
void on_library_load(CPUState *env, target_ulong pc, char *lib_name, target_ulong base_addr);
void on_all_livevar_iter(CPUState *env, target_ulong pc, liveVarCB f, void *args);

void on_funct_livevar_iter(CPUState *env, target_ulong pc, liveVarCB f, void *args);

void on_global_livevar_iter(CPUState *env, target_ulong pc, liveVarCB f, void *args);



#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <dwarf.h>
#include <libdwarf.h>

}
#include "../callstack_instr/callstack_instr.h"
#include "../common/prog_point.h"
#include "../callstack_instr/callstack_instr_ext.h"

const char *guest_debug_path = NULL;
const char *host_debug_path = NULL;
const char *proc_to_monitor = NULL;
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

#include "pri_dwarf_int_fns.h"
PPP_PROT_REG_CB(on_pri_dwarf_line_change);
}
PPP_CB_BOILERPLATE(on_pri_dwarf_line_change);


#include <vector>
#include <map>
#include <set>
#include <string>
#include <algorithm>
//#include <boost/algorithm/string/join.hpp>
#define MAX_FILENAME 256
Dwarf_Unsigned prev_line = 0, cur_line;
Dwarf_Addr prev_function = 0, cur_function;
Dwarf_Addr prev_line_pc = 0;
char *prev_file_name = NULL;
std::string prev_funct_name = std::string("");
bool inExecutableSource = false;

//////// consider putting this in pri
// current process
OsiProc *current_proc = NULL;
OsiModule *current_lib = NULL;
OsiModules *current_libs = NULL;
bool proc_diff(OsiProc *p_curr, OsiProc *p_new) {
    if (p_curr == NULL) {
        return (p_new != NULL);
    }
    if (p_curr->offset != p_new->offset
        || p_curr->asid != p_new->asid
        || p_curr->pid != p_new->pid
        || p_curr->ppid != p_new->ppid)
        return true;
    return false;
}
bool proc_changed = false;
bool bbbexec_check_proc = false;
//////// end effects plugin globals

// asid changed -- start looking for valid proc info
int asid_changed(CPUState *env, target_ulong old_asid, target_ulong new_asid) {
    bbbexec_check_proc = true;
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
std::map<Dwarf_Addr,std::string> funcaddrs;
//std::map<Dwarf_Addr,std::string> funcaddrs_ret;
//std::map<Dwarf_Addr,std::string> funcparams;
std::vector<std::string> processed_libs;
std::map<std::string, Dwarf_Addr> dynl_functions;
std::map<Dwarf_Addr, std::string> addr_to_dynl_function;
std::map<target_ulong, std::pair<Dwarf_Debug*, int>> libBaseAddr_to_debugInfo;
std::set<std::string> mods_seen;

struct VarInfo {
    void *var_type;
    std::string var_name;
    Dwarf_Locdesc** locations;
    Dwarf_Signed num_locations;

    VarInfo(void *var_type, std::string var_name,
            Dwarf_Locdesc** locations, Dwarf_Signed num_locations) :
        var_type(var_type), var_name(var_name),
        locations(locations), num_locations(num_locations) {}
};

std::map<Dwarf_Addr,std::vector<VarInfo>> funcvars;
std::vector<VarInfo> global_var_list;

typedef struct LineRange {
    Dwarf_Addr lowpc, highpc, function_addr;
    char *filename;
    unsigned long line_number;
    Dwarf_Unsigned line_off;

    LineRange(Dwarf_Addr lowpc, Dwarf_Addr highpc, unsigned long line_number,
            char *filename, Dwarf_Addr function_addr, Dwarf_Unsigned line_off) :
        lowpc(lowpc), highpc(highpc), function_addr(function_addr),
        filename(filename), line_number(line_number), line_off(line_off) {}
} LineRange;
std::vector<LineRange> line_range_list;
std::vector<LineRange> fn_start_line_range_list;
std::map<std::string, LineRange> fn_name_to_line_info;

// don't need this, but may want it in the future
//std::map<Dwarf_Addr, Dwarf_Unsigned> funct_to_cu_base;
// use this to calculate a the value of a function's base pointer at a given pc
// curfunction -> location description list for FP
std::map<Dwarf_Addr,std::pair<Dwarf_Locdesc**, Dwarf_Signed>> funct_to_framepointers;


bool sortRange(const LineRange &x1,
               const LineRange &x2){
    return x1.lowpc < x2.lowpc ||
           x1.highpc < x2.highpc;
}

struct CompareRangeAndPC
{
    bool operator () (const LineRange &ln_info,
                    const Dwarf_Addr &pc) const{
        //if (ln_info.lowpc <= pc && ln_info.highpc >= pc){
        if (ln_info.lowpc <= pc && ln_info.highpc > pc){
            return 0;
        }
        else
            return ln_info.lowpc < pc;
    }
};
/*
    required string file_callee = 1;
    required string function_name_callee = 2;
    required uint64 line_number_callee = 3;
    required string file_caller = 4;
    required uint64 line_number_caller = 5;
*/
void pri_dwarf_plog(char *file_callee, char *fn_callee, uint64_t lno_callee,
        char *file_caller, uint64_t lno_caller, bool isCall) {
    // setup
    Panda__DwarfCall *dwarf = (Panda__DwarfCall *) malloc (sizeof (Panda__DwarfCall));
    *dwarf = PANDA__DWARF_CALL__INIT;
    // assign values
    dwarf->function_name_callee = fn_callee;
    dwarf->file_callee = file_callee;
    dwarf->line_number_callee = lno_callee;
    dwarf->file_caller = file_caller;
    dwarf->line_number_caller = lno_caller;

    Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
    // create a call or ret message
    if (isCall){
        ple.dwarf_call = dwarf;
    }
    else{
        ple.dwarf_ret = dwarf;
    }
    // write to log file
    if (pandalog) {
        pandalog_write_entry(&ple);
    }
    free(dwarf);
}

Dwarf_Addr prev_pc = 0;
uint32_t prev_pc_count = 0;


void die(const char* fmt, ...) {
    va_list args;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

static int
get_form_values(Dwarf_Attribute attrib,
    Dwarf_Half * theform, Dwarf_Half * directform) {
    Dwarf_Error err = 0;
    int res = dwarf_whatform(attrib, theform, &err);
    dwarf_whatform_direct(attrib, directform, &err);
    return res;
}

// stolen from libdwarf dwarfdump implementation
// in order to read a signed attribute from a die
static int
dwarf_upper_bound(Dwarf_Die the_die,
    Dwarf_Unsigned *sd,
    Dwarf_Error * err)
{
    Dwarf_Attribute attr;
    int rc = 0;
    rc = dwarf_attr(the_die, DW_AT_upper_bound, &attr, err);
    if (rc == DW_DLV_OK) {
        rc = dwarf_formudata(attr, sd, err);
        if (rc == DW_DLV_ERROR){
             assert (1==0);
        }
        else if (rc == DW_DLV_NO_ENTRY) {
            printf("no entry \"upper_bound\"\n");
            *sd = 1;
        }
        return rc;
    }
    return rc;
}

// This stuff stolen from linux-user/elfload.c
// Would have preferred to just use libelf, but QEMU stupidly
// ships an incompatible copy of elf.h so the compiler finds
// it before any other versions, making libelf unusable. Luckily
// this does not seem to affect libdwarf.

// QEMU's stupid version of elf.h
#define ELF_CLASS ELFCLASS32
#define ELF_DATA  ELFDATA2LSB
#define elf_check_arch(x) ( ((x) == EM_386) || ((x) == EM_486) )
#include "elf.h"

static bool elf_check_ident(struct elfhdr *ehdr)
{
    return (ehdr->e_ident[EI_MAG0] == ELFMAG0
            && ehdr->e_ident[EI_MAG1] == ELFMAG1
            && ehdr->e_ident[EI_MAG2] == ELFMAG2
            && ehdr->e_ident[EI_MAG3] == ELFMAG3
            && ehdr->e_ident[EI_CLASS] == ELF_CLASS
            && ehdr->e_ident[EI_DATA] == ELF_DATA
            && ehdr->e_ident[EI_VERSION] == EV_CURRENT);
}

static bool elf_check_ehdr(struct elfhdr *ehdr)
{
    return (elf_check_arch(ehdr->e_machine)
            && ehdr->e_ehsize == sizeof(struct elfhdr)
            && ehdr->e_phentsize == sizeof(struct elf_phdr)
            && ehdr->e_shentsize == sizeof(struct elf_shdr)
            && (ehdr->e_type == ET_EXEC || ehdr->e_type == ET_DYN));
}

uint64_t elf_get_baseaddr(const char *fname, const char *basename, target_ulong actual_base_address) {
    // XXX: note: byte swapping omitted
    // XXX: 64-bit support omitted. Mess with ELFCLASS
    struct elfhdr ehdr;
    struct elf_phdr *phdr;
    struct elf_shdr *shdr;
    uint16_t shstrndx;
    uint32_t load_addr, loaddr, hiaddr;
    int i, retval;

    FILE *f = fopen(fname, "rb");
    if (0 == fread(&ehdr, sizeof(ehdr), 1, f)){
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

    phdr = (struct elf_phdr *) malloc(ehdr.e_phnum * sizeof(struct elf_phdr));
    fseek(f, ehdr.e_phoff, SEEK_SET);
    retval = fread(phdr, sizeof(struct elf_phdr), ehdr.e_phnum, f);
    if (retval != ehdr.e_phnum) {
        free(phdr);
        return -1;
    }

    shdr = (struct elf_shdr *) malloc(ehdr.e_shnum * sizeof(struct elf_shdr));
    fseek(f, ehdr.e_shoff, SEEK_SET);
    retval = fread(shdr, sizeof(struct elf_shdr), ehdr.e_shnum, f);
    if (retval != ehdr.e_shnum) {
        free(shdr);
        return -1;
    }
    shstrndx = ehdr.e_shstrndx;
    if (shstrndx == SHN_UNDEF){
        printf("no section table\n");
        return -1;
    }
    else if (shstrndx == 0xffff){
        printf("Actual index for string table is in sh_link of string table section\n");
        return -1;
    }
    //printf("shstrndx: %d\n", ehdr.e_shstrndx);
    //Elf32_Off str_table_off = (ehdr.e_shentsize*ehdr.e_shstrndx) + ehdr.e_shoff;
    //printf("shstrtable file offset: %d\n", str_table_off);
    //printf("shstrtable size: %d\n", shdr[ehdr.e_shstrndx].sh_size);
    //printf("shstrtable offset: %d\n", shdr[ehdr.e_shstrndx].sh_offset);
    char *shstrtable = (char *) malloc(shdr[ehdr.e_shstrndx].sh_size);
    fseek(f, shdr[ehdr.e_shstrndx].sh_offset, SEEK_SET);
    if (shdr[ehdr.e_shstrndx].sh_size != fread(shstrtable, 1,  shdr[ehdr.e_shstrndx].sh_size, f)){
        printf("Wasn't able to successfully read string table from file\n");
        return -1;
    }

    // analyze section headers for .rel.plt section
    // and .plt (SHT_PROGBITS) for base address of dynamically linked function names
    ssize_t relplt_size = 0;
    Elf32_Rel *relplt = NULL;
    Elf32_Sym *symtab = NULL;
    Elf32_Sym *dynsym = NULL;
    char *strtable = NULL;
    char *dynstrtable = NULL;
    uint32_t plt_addr;
    for (i = 0; i < ehdr.e_shnum; ++i) {
        if (strcmp(".plt", &shstrtable[shdr[i].sh_name]) == 0){
            plt_addr = shdr[i].sh_addr + 0x10;
            //printf("got .plt base address: %x\n", shdr[i].sh_addr);
        }
        else if (strcmp(".strtab", &shstrtable[shdr[i].sh_name]) == 0){
            //printf("got .strtab\n");
            strtable= (char *) malloc(shdr[i].sh_size);
            fseek(f, shdr[i].sh_offset, SEEK_SET);
            if (shdr[i].sh_size != fread(strtable, 1, shdr[i].sh_size, f)){
                printf("Wasn't able to successfully populate the dynstrtable\n");
                return -1;
            }
        }
        else if (strcmp(".dynstr", &shstrtable[shdr[i].sh_name]) == 0){
            //printf("got .dynstr\n");
            dynstrtable= (char *) malloc(shdr[i].sh_size);
            fseek(f, shdr[i].sh_offset, SEEK_SET);
            if (shdr[i].sh_size != fread(dynstrtable, 1, shdr[i].sh_size, f)){
                printf("Wasn't able to successfully populate the dynstrtable\n");
                return -1;
            }
        }
        else if (strcmp(".rel.plt", &shstrtable[shdr[i].sh_name]) == 0){
            //printf("got .rel.plt\n");
            relplt = (Elf32_Rel *) malloc(shdr[i].sh_size);
            relplt_size = shdr[i].sh_size/sizeof(Elf32_Rel);
            fseek(f, shdr[i].sh_offset, SEEK_SET);
            if (shdr[i].sh_size != fread(relplt, 1, shdr[i].sh_size, f)){
                printf("Wasn't able to successfully populate the reltab\n");
                return -1;
            }
        }
        else if (strcmp(".dynsym", &shstrtable[shdr[i].sh_name]) == 0){
            //printf("got .dynsym\n");
            dynsym = (Elf32_Sym *) malloc(shdr[i].sh_size);
            fseek(f, shdr[i].sh_offset, SEEK_SET);
            if (shdr[i].sh_size != fread(dynsym, 1, shdr[i].sh_size, f)){
                printf("Wasn't able to successfully populate the .dynsym\n");
                return -1;
            }
        }
        else if (strcmp(".symtab", &shstrtable[shdr[i].sh_name]) == 0){
            //printf("got .symtab\n");
            symtab = (Elf32_Sym *) malloc(shdr[i].sh_size);
            fseek(f, shdr[i].sh_offset, SEEK_SET);
            if (shdr[i].sh_size != fread(symtab, 1, shdr[i].sh_size, f)){
                printf("Wasn't able to successfully populate the symtab\n");
                return -1;
            }
        }
    }
    /* Find the maximum size of the image and allocate an appropriate
       amount of memory to handle that.  */
    loaddr = -1;
    for (i = 0; i < ehdr.e_phnum; ++i) {
        if (phdr[i].p_type == PT_LOAD) {
            uint32_t a = phdr[i].p_vaddr;
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
    if (relplt == NULL || dynsym == NULL || dynstrtable == NULL){
        return load_addr;
    }
    // put libname in the a processed_libs list to iterate through when we process the function later on
    processed_libs.push_back(std::string(basename));
    // now add plt functions to global plt function mapping
    Dwarf_Addr plt_fun_addr;
    std::string plt_fun_name;
    for (i = 0; i < relplt_size; i++){
        if (norelro){
            plt_fun_addr = (unsigned long)plt_addr+16*i;
        }
        else {
            plt_fun_addr = (unsigned long)plt_addr+16*i + actual_base_address;
        }
        uint32_t f_name_strndx = dynsym[ELF32_R_SYM(relplt[i].r_info)].st_name;
        plt_fun_name = std::string(&dynstrtable[f_name_strndx]);
        //printf(" [%d] r_offset: %x, .text location: %x,  sym_name: %s\n", i, relplt[i].r_offset, plt_addr+16*i,  &dynstrtable[f_name_strndx]);
        // check if we have already processed this symbol name
        auto it = fn_name_to_line_info.find(plt_fun_name);
        if (it != fn_name_to_line_info.end()){
            const LineRange &lr = it->second;
            line_range_list.push_back(LineRange(plt_fun_addr, plt_fun_addr,
                        lr.line_number, lr.filename, lr.function_addr, lr.line_off));
        }
        else {
            dynl_functions[std::string(basename) + ":plt!" + plt_fun_name] = plt_fun_addr;
            addr_to_dynl_function[plt_fun_addr] = "plt!" + plt_fun_name;
        }
    }
    // sort the line_range_list because we changed it
    std::sort(line_range_list.begin(), line_range_list.end(), sortRange);

    return load_addr;
}

void enumerate_die_attrs(Dwarf_Die the_die)
{
    Dwarf_Error err;
    Dwarf_Attribute* attrs;
    Dwarf_Attribute attr;
    Dwarf_Signed attrcount;
    int i;
    /* Grab the DIEs attributes for display */
    if (dwarf_attrlist(the_die, &attrs, &attrcount, &err) != DW_DLV_OK)
    {
        printf("    Error in dwarf_attlist\n");
        return;
    }
    for (i = 0; i < attrcount; ++i) {
        Dwarf_Half attrcode;
        if (dwarf_whatattr(attrs[i], &attrcode, &err) != DW_DLV_OK)
        {
            printf("    Error in dwarf_whatattr\n");
            return;
        }
        if (dwarf_attr(the_die, attrcode, &attr, &err) == DW_DLV_OK)
            printf("    Attr number 0x%x, Attr value 0x%lx\n", attrcode, (unsigned long) attr);
    }

}
Dwarf_Unsigned get_struct_member_offset(Dwarf_Die the_die) {
    Dwarf_Error err;
    Dwarf_Bool hasLocation;
    Dwarf_Attribute locationAttr;
    Dwarf_Locdesc **locdesclist = NULL;
    Dwarf_Signed loccnt = 0;

    if (dwarf_hasattr(the_die, DW_AT_data_member_location, &hasLocation, &err) != DW_DLV_OK)
        die("Error in dwarf attr, for determining existences of location attr\n");
    else if (hasLocation){
        if (dwarf_attr(the_die, DW_AT_data_member_location, &locationAttr, &err) != DW_DLV_OK)
            die("Error obtaining location attr\n");
        // dwarf_formexprloc(attr, expr_len, block_ptr, &err);
        else if (dwarf_loclist_n(locationAttr, &locdesclist, &loccnt, &err) != DW_DLV_OK){
            char *die_name = 0;
            if (dwarf_diename(the_die, &die_name, &err) != DW_DLV_OK){
                die("Not able to get location list for var without a name.  Probably optimized out\n");
            }
            else{
                die("Not able to get location list for \'%s\'.  Probably optimized out\n", die_name);
            }
        }
        else {
            assert(loccnt == 1);
            assert(locdesclist[0]->ld_cents == 1);
            assert(locdesclist[0]->ld_s[0].lr_atom == DW_OP_plus_uconst);
            return locdesclist[0]->ld_s[0].lr_number & 0xff;
        }
        printf("Attribute does not have a location\n");
    }
    // does not have location attribute or error in getting location data
    return -1;

}

int die_get_type_size (Dwarf_Debug dbg, Dwarf_Die the_die){
    Dwarf_Error err;
    Dwarf_Half tag;
    int rc;
    //char *die_name = 0;
    Dwarf_Attribute type_attr;
    Dwarf_Off offset;
    Dwarf_Die type_die;
    Dwarf_Die cur_die;

    cur_die = the_die;
    // initialize tag to DW_TAG_pointer_type to enter the while loop
    tag = DW_TAG_typedef;
    while (tag == DW_TAG_typedef       ||
           tag == DW_TAG_volatile_type ||
           tag == DW_TAG_const_type)
    {
        rc = dwarf_attr (cur_die, DW_AT_type, &type_attr, &err);
        if (rc == DW_DLV_ERROR){
            // error getting type
            //die("Error getting type attr for var %s\n", die_name;
            return -1;
        }
        else if (rc == DW_DLV_NO_ENTRY)
        {
            // http://web.mit.edu/freebsd/head/cddl/contrib/opensolaris/tools/ctf/cvt/dwarf.c
            // the lack of a type reference implies a reference to a void type
            return -1;
        }
        else
        {

            // http://stackoverflow.com/questions/12233061/any-experienced-dwarf-parsers-users-need-to-get-the-attribute-type-offset-of-a
            // user swann outlines these two functions are necessary to jump to a dwarf reference

            dwarf_global_formref(type_attr, &offset, &err);
            dwarf_offdie_b(dbg, offset, 1, &type_die, &err);
            // end swann code
            dwarf_tag(type_die, &tag, &err);
            cur_die = type_die;
            switch (tag)
            {
                case DW_TAG_union_type: // union has byte_size field like structure_type and base_type
                case DW_TAG_structure_type:
                case DW_TAG_base_type:
                    // hit base_type, do taint based on size of base type
                    {
                        Dwarf_Unsigned base_typesize;
                        rc = dwarf_bytesize(type_die, &base_typesize, &err);
                        if (rc == DW_DLV_OK){
                            return base_typesize;
                        }
                        else {
                            return -1;
                        }
                    }
                case DW_TAG_ptr_to_member_type: // what to do here?
                case DW_TAG_pointer_type: // increment derefs
                    return sizeof(target_ulong);
                case DW_TAG_array_type:
                    {
                        Dwarf_Half array_child_tag;
                        Dwarf_Unsigned elem_typesize;
                        Dwarf_Unsigned array_typesize;
                        Dwarf_Die array_child;
                        if (dwarf_child(type_die,
                                    &array_child, &err) != DW_DLV_OK){
                             break;
                        }
                        dwarf_tag(array_child, &array_child_tag, &err);
                        assert(array_child_tag == DW_TAG_subrange_type);
                        // fix this
                        elem_typesize = die_get_type_size(dbg, type_die);
                        rc = dwarf_upper_bound(array_child, 
                                &array_typesize, 
                                &err);
                        // array size is 0 than we likely have a 0 length
                        // array which is common at the end of structs to make a
                        // flexible length struct
                        array_typesize = (rc == DW_DLV_OK ?
                                          array_typesize : 0) + 1;
                        return array_typesize*elem_typesize;
                    }
                // can probably treat it as querying taint on an int
                case DW_TAG_enumeration_type:
                    return 4;
                // what to do here? shold not get here, so return -1
                case DW_TAG_constant:
                case DW_TAG_unspecified_parameters:
                case DW_TAG_imported_declaration:
                case DW_TAG_subroutine_type:
                    return -1;
                // continue enumerating type to get actual type
                // just "skip" these types by continuing to descend type tree
                case DW_TAG_typedef:
                case DW_TAG_volatile_type:
                case DW_TAG_const_type:
                    break;
                default: // we may want to do something different for the default case
                    printf("Got unknown DW_TAG: 0x%x\n", tag);
                    exit(1);
            }
        }
    }
    return -1;
}

std::string getNameFromDie(Dwarf_Die the_die){
    Dwarf_Error err;
    int rc;
    char *die_name = 0;
    std::string ret_string;

    rc = dwarf_diename(the_die, &die_name, &err);
    if (rc == DW_DLV_ERROR) {
        die("Error in dwarf_diename\n");
    }
    if (rc != DW_DLV_OK) ret_string = "?";
    else ret_string = die_name;
    return ret_string;
}

void __dwarf_type_iter (CPUState *env, target_ulong base_addr, LocType loc_t, Dwarf_Debug dbg,
        Dwarf_Die the_die, const char *astnodename, dwarfTypeCB cb, int recursion_level);

void dwarf_type_iter (CPUState *env, target_ulong base_addr, LocType loc_t, DwarfVarType *var_ty, dwarfTypeCB cb,
        int recursion_level){
    Dwarf_Error err;
    int rc;
    Dwarf_Debug dbg = var_ty->dbg;
    Dwarf_Die the_die = var_ty->var_die;
    // We need to get the die name in order to build ast nodenames
    char *die_name = 0;
    rc = dwarf_diename(the_die, &die_name, &err);
    if (rc != DW_DLV_OK) {
        die("Error: no var name. Cannot make astnodename\n");
        return;
    }
    __dwarf_type_iter (env, base_addr, loc_t, dbg, the_die, die_name, cb, recursion_level);
    return;
}
void __dwarf_type_iter (CPUState *env, target_ulong base_addr, LocType loc_t,
        Dwarf_Debug dbg, Dwarf_Die the_die, const char *astnodename, dwarfTypeCB cb, int recursion_level){
    if (recursion_level <= 0) return;
    Dwarf_Error err;
    Dwarf_Half tag;
    int rc;
    std::string cur_astnodename = astnodename;
    char *die_name = 0;
    Dwarf_Attribute type_attr;
    Dwarf_Off offset;
    Dwarf_Die type_die;
    Dwarf_Die cur_die;
    target_ulong cur_base_addr = base_addr;

    cur_die = the_die;
    // initialize tag to DW_TAG_pointer_type to enter the while loop
    tag = DW_TAG_pointer_type;
    while (tag == DW_TAG_pointer_type  ||
           tag == DW_TAG_typedef       ||
           tag == DW_TAG_array_type    ||
           tag == DW_TAG_volatile_type ||
           tag == DW_TAG_const_type)
    {
        rc = dwarf_attr (cur_die, DW_AT_type, &type_attr, &err);
        if (rc == DW_DLV_ERROR){
            // error getting type
            die("Error getting type attr for var %s\n", cur_astnodename.c_str());
            return;
        }
        else if (rc == DW_DLV_NO_ENTRY)
        {
            // http://web.mit.edu/freebsd/head/cddl/contrib/opensolaris/tools/ctf/cvt/dwarf.c
            // the lack of a type reference implies a reference to a void type
            return;
        }
        else
        {

            // http://stackoverflow.com/questions/12233061/any-experienced-dwarf-parsers-users-need-to-get-the-attribute-type-offset-of-a
            // user swann outlines these two functions are necessary to jump to a dwarf reference

            dwarf_global_formref(type_attr, &offset, &err);
            dwarf_offdie_b(dbg, offset, 1, &type_die, &err);
            // end swann code
            dwarf_tag(type_die, &tag, &err);
            cur_die = type_die;
            switch (tag)
            {
                case DW_TAG_structure_type:
                    //printf("  [+] structure_type: enumerating . . .\n");
                    {
                        Dwarf_Unsigned struct_offset;
                        std::string temp_name;
                        rc = dwarf_diename(type_die, &die_name, &err);
                        if (rc != DW_DLV_OK)
                            die_name = (char *) "?";
                        Dwarf_Die struct_child;
                        if (dwarf_child(type_die, &struct_child, &err) != DW_DLV_OK)
                        {
                            //printf("  Couldn't parse struct for var: %s\n",cur_astnodename.c_str() );
                            return;
                        }
                        char *field_name;
                        while (1) // enumerate struct arguments
                        {
                            rc = dwarf_siblingof(dbg, struct_child, &struct_child, &err);
                            if (rc == DW_DLV_ERROR) {
                                die("Struct: Error getting sibling of DIE\n");
                                break;
                            }
                            else if (rc == DW_DLV_NO_ENTRY) {
                                break;
                            }
                            rc = dwarf_diename(struct_child, &field_name, &err);
                            struct_offset = get_struct_member_offset(struct_child);
                            if (rc != DW_DLV_OK){
                                break;
                            }
                            temp_name = "(" + cur_astnodename + ")." + field_name;
                            //printf(" struct: %s, offset: %llu\n", temp_name.c_str(), struct_offset);
                            __dwarf_type_iter(env, cur_base_addr + struct_offset, loc_t, dbg,
                                           struct_child, temp_name.c_str(), cb, recursion_level - 1);
                        }
                        return;
                    }
                case DW_TAG_base_type:
                    // hit base_type, do taint based on size of base type
                    {
                        Dwarf_Unsigned base_typesize;
                        rc = dwarf_bytesize(type_die, &base_typesize, &err);
                        if (rc == DW_DLV_OK){
                            rc = dwarf_diename(type_die, &die_name, &err);
                            //printf("Querying: (%s) %s\n", die_name, cur_astnodename.c_str());
                            cb(cur_base_addr, loc_t, base_typesize, cur_astnodename.c_str());
                        }
                        break;
                    }
                case DW_TAG_pointer_type: // increment derefs
                    // check if it is a pointer to the char type, if so
                    // strnlen = true and then return
                    {
                        //printf("Querying: (*) %s\n", cur_astnodename.c_str());
                        cb(cur_base_addr, loc_t, sizeof(cur_base_addr),
                                cur_astnodename.c_str());
                        cur_astnodename = "*(" + cur_astnodename + ")";
                        if (loc_t == LocMem) {
                            rc = panda_virtual_memory_rw(env, cur_base_addr,
                                    (uint8_t *)&cur_base_addr,
                                    sizeof(cur_base_addr), 0);
                            if (rc == -1){
                                //printf("Could not dereference pointer so done"
                                       //" tainting\n");
                                return;
                            }
                        }
                        else if (loc_t == LocReg){
                            if (cur_base_addr < CPU_NB_REGS)
                                cur_base_addr = env->regs[cur_base_addr];
                            else
                                return;
                        }
                        else {
                            // shouldn't get herer
                            abort();
                        }
                        Dwarf_Die tmp_die;
                        rc = dwarf_attr (cur_die, DW_AT_type, &type_attr, &err);
                        dwarf_global_formref(type_attr, &offset, &err);
                        dwarf_offdie_b(dbg, offset, 1, &tmp_die, &err);
                        dwarf_tag(type_die, &tag, &err);
                        rc = dwarf_diename(tmp_die, &die_name, &err);
                        // either query element as a null terminated char *
                        // or a one element array of the type of whatever
                        // we are pointing to
                        if (rc == DW_DLV_OK){
                            if (0 == strcmp("char", die_name)){
                                //printf("Querying: (char *) %s\n", cur_astnodename.c_str());
                                cb(cur_base_addr, loc_t, -1, cur_astnodename.c_str());
                                return;
                            }
                        }
                        break;
                    }
                case DW_TAG_array_type:
                    {
                        Dwarf_Half array_child_tag;
                        Dwarf_Unsigned elem_typesize;
                        Dwarf_Unsigned array_typesize;
                        Dwarf_Die array_child;
                        if (dwarf_child(type_die,
                                    &array_child, &err) != DW_DLV_OK){
                             break;
                        }
                        dwarf_tag(array_child, &array_child_tag, &err);
                        assert(array_child_tag == DW_TAG_subrange_type);
                        // fix this
                        elem_typesize = die_get_type_size(dbg, type_die);
                        //printf("Querying: ([]) %s\n", cur_astnodename.c_str());
                        rc = dwarf_upper_bound(array_child, 
                                &array_typesize, 
                                &err);
                        // array size is 0 than we likely have a 0 length
                        // array which is common at the end of structs to make a
                        // flexible length struct
                        array_typesize = (rc == DW_DLV_OK ?
                                          array_typesize : 0) + 1;
                        cb(cur_base_addr, loc_t, array_typesize*elem_typesize, cur_astnodename.c_str());
                        return;
                    }
                // can probably treat it as querying taint on an int
                case DW_TAG_enumeration_type:
                    //printf("Querying: (enum) %s\n", cur_astnodename.c_str());
                    cb(cur_base_addr, loc_t, 4, cur_astnodename.c_str());
                    return;
                case DW_TAG_union_type: // what to do here? should just treat it like a struct
                    break;
                case DW_TAG_subroutine_type: // what to do here? just going to default, and continuing to enum die
                    //printf("Querying: (fn) %s\n", cur_astnodename.c_str());
                    cb(cur_base_addr, loc_t, sizeof(cur_base_addr), cur_astnodename.c_str());
                    break;
                case DW_TAG_ptr_to_member_type: // what to do here?
                    break;
                // continue enumerating type to get actual type
                case DW_TAG_typedef:
                // just "skip" these types by continuing to descend type tree
                case DW_TAG_volatile_type:
                case DW_TAG_const_type:
                case DW_TAG_imported_declaration:
                case DW_TAG_unspecified_parameters:
                case DW_TAG_constant:
                    break;
                default: // we may want to do something different for the default case
                    printf("Got unknown DW_TAG: 0x%x\n", tag);
                    exit(1);
            }
        }
    }
    return;
}
const char *dwarf_type_to_string ( DwarfVarType *var_ty ){
    Dwarf_Error err;
    Dwarf_Half tag;
    int rc;
    std::string argname;
    char *die_name = 0;
    Dwarf_Attribute type_attr;
    Dwarf_Off offset;
    Dwarf_Die type_die;
    Dwarf_Die cur_die;
    std::string type_name;
    Dwarf_Debug dbg = var_ty->dbg;
    Dwarf_Die the_die = var_ty->var_die;

    rc = dwarf_diename(the_die, &die_name, &err);

    if (rc == DW_DLV_ERROR) {
        die("Error in dwarf_diename\n");
        die_name = (char *)"?";
    }
    // if we can't get the argname, that is ok, we can still get the type of the argument
    // and since we are assuming arguments are pushed on the stack, we can still find it's
    // location by examining the stack pointer
    if (rc != DW_DLV_OK) argname = "?";
    else argname = die_name;

    cur_die = the_die;
    type_name = "";
    // initialize tag to DW_TAG_pointer_type to enter the while loop
    tag = DW_TAG_pointer_type;
    while (tag == DW_TAG_pointer_type  ||
           tag == DW_TAG_typedef       ||
           tag == DW_TAG_array_type    ||
           tag == DW_TAG_volatile_type ||
           tag == DW_TAG_const_type)
    {
        rc = dwarf_attr (cur_die, DW_AT_type, &type_attr, &err);
        if (rc == DW_DLV_ERROR){
            // error getting type
            die("Error getting type name for var %s\n", die_name);
            return type_name.c_str();
        }
        else if (rc == DW_DLV_NO_ENTRY)
        {
            // http://web.mit.edu/freebsd/head/cddl/contrib/opensolaris/tools/ctf/cvt/dwarf.c
            // the lack of a type reference implies a reference to a void type
            //enumerate_die_attrs(cur_die);
            type_name += "void";
            break;
        }
        else
        {
            /*
             * http://stackoverflow.com/questions/12233061/any-experienced-dwarf-parsers-users-need-to-get-the-attribute-type-offset-of-a
             * user swann outlines these two functions are necessary to jump to a dwarf reference
             */
            dwarf_global_formref(type_attr, &offset, &err);
            dwarf_offdie_b(dbg, offset, 1, &type_die, &err);
            // end swann code

            dwarf_tag(type_die, &tag, &err);
            cur_die = type_die;
            switch (tag)
            {
                case DW_TAG_structure_type:
                    //printf("  [+] structure_type: enumerating . . .\n");
                    rc = dwarf_diename(type_die, &die_name, &err);
                    if (rc != DW_DLV_OK) type_name += "? ";
                    else type_name += die_name;
                    Dwarf_Die struct_child;
                    if (dwarf_child(type_die, &struct_child, &err) != DW_DLV_OK)
                    {
                        //printf("  Couldn't parse struct for var: %s\n",argname.c_str() );
                        return type_name.c_str();
                    }
                    char *field_name;
                    while (1) // enumerate struct arguments
                    {
                        rc = dwarf_siblingof(dbg, struct_child, &struct_child, &err);
                        if (rc == DW_DLV_ERROR) {
                            die("Struct: Error getting sibling of DIE\n");
                            break;
                        }
                        else if (rc == DW_DLV_NO_ENTRY) {
                            break;
                        }

                        rc = dwarf_diename(struct_child, &field_name, &err);
                        if (rc != DW_DLV_OK)
                            strncpy(field_name, "?\0", 2);
                        //printf("    [+] %s\n", field_name);
                    }
                    break;
                case DW_TAG_union_type: // what to do here? should just treat it like a struct?
                    break;
                case DW_TAG_base_type:
                    // hit base_type, do something
                    rc = dwarf_diename(type_die, &die_name, &err);
                    if (rc != DW_DLV_OK) type_name += "?";
                    else type_name += die_name;
                    break;
                case DW_TAG_pointer_type: // increment derefs
                    type_name = "*" + type_name;
                    break;
                case DW_TAG_array_type:
                    type_name += "[]";
                    break;
                case DW_TAG_enumeration_type:
                    type_name += "enum";
                    break;
                case DW_TAG_subroutine_type:
                    type_name += "func_pointer ";
                    break;
                case DW_TAG_volatile_type:
                    type_name += "volatile";
                    break;
                case DW_TAG_const_type:
                    type_name += "const ";
                    break;
                // just "skip" these types by continuing to descend type tree
                case DW_TAG_typedef: // continue enumerating type to get actual type
                case DW_TAG_ptr_to_member_type: // what to do here?
                case DW_TAG_imported_declaration:
                case DW_TAG_unspecified_parameters:
                case DW_TAG_constant:
                    break;
                default: // we may want to do something different for the default case
                    printf("Got unknown DW_TAG: 0x%x\n", tag);
                    exit(1);
            }
        }
    }

    return type_name.c_str();
}

// Copies the location list for a particular attrbibute to locdesclist_copy in order to use the location information
// at future points in the program
// From what I have observed, attr must be either DW_AT_location or DW_AT_frame_base, but it could theoretically be
// any attribute that represents a location list
// relocates the address range for DW_OP_ADDRs and the "live ranges" for each variable
int get_die_loc_info(Dwarf_Debug dbg, Dwarf_Die the_die, Dwarf_Half attr, Dwarf_Locdesc ***locdesclist_out, Dwarf_Signed *loccnt, uint64_t base_address, uint64_t cu_base_address,bool needs_reloc) {
    Dwarf_Error err;
    Dwarf_Bool hasLocation;
    Dwarf_Attribute locationAttr;
    Dwarf_Locdesc **locdesclist;
    int i, j;


    if (dwarf_hasattr(the_die, attr, &hasLocation, &err) != DW_DLV_OK)
        die("Error in dwarf attr, for determining existences of location attr\n");
    else if (hasLocation){
        if (dwarf_attr(the_die, attr, &locationAttr, &err) != DW_DLV_OK)
            die("Error obtaining location attr\n");
        // dwarf_formexprloc(attr, expr_len, block_ptr, &err);
        // this is slow, figure out a faster way to get the location information
        else if (dwarf_loclist_n(locationAttr, &locdesclist, loccnt, &err) != DW_DLV_OK){
            char *die_name = 0;
            if (dwarf_diename(the_die, &die_name, &err) != DW_DLV_OK){
                die("Not able to get location list for var without a name.  Probably optimized out\n");
            }
            else{
                die("Not able to get location list for \'%s\'.  Probably optimized out\n", die_name);
            }
        }
        else {
            *locdesclist_out = locdesclist;
            //*locdesclist_out = (Dwarf_Locdesc **) malloc(sizeof(Dwarf_Locdesc *)*(*loccnt));
            //printf("Variable locs: %llu [", *loccnt);
            for (i = 0; i < *loccnt; i++){
                // copy data to new malloc locdesc that won't be dealloc'd in dwarf cleanup function
                //Dwarf_Locdesc *locdesc_copy = (Dwarf_Locdesc *) malloc(sizeof(Dwarf_Locdesc));
                //memcpy(locdesc_copy, locdesclist[i], sizeof(Dwarf_Locdesc));
                //Dwarf_Loc *loc_recs = (Dwarf_Loc *) malloc(locdesclist[i]->ld_cents*sizeof(Dwarf_Loc));
                //memcpy(loc_recs, locdesclist[i]->ld_s, locdesclist[i]->ld_cents*sizeof(Dwarf_Loc));
                //(*locdesclist_out)[i] = locdesc_copy;
                //(*locdesclist_out)[i]->ld_s = loc_recs;

                // patch lo and hi address in locdesc structure
                // for variable "liveness" - this is a different usage of word live than typical uses
                // live in this context means that the value at the location of the variable
                // represents the actual value of the variable
                // if lo = 0 and hi = 0xffffffff then variable is "live" for total scope of function
                // if hipc and lopc both equal 0 than object has been optimized out
                // if hi is 0xffffffff and lo does't equal 0 then this will add base address to hi
                // im basically assuming that hi will not be 0xffffffff unless the variable is
                // live for all scope of program
                if ((Dwarf_Addr) -1 != (*locdesclist_out)[i]->ld_hipc){
                    if (needs_reloc){
                        (*locdesclist_out)[i]->ld_lopc += base_address;
                        (*locdesclist_out)[i]->ld_hipc += base_address;
                        for (j = 0; j < (*locdesclist_out)[i]->ld_cents; j++){
                            if ((*locdesclist_out)[i]->ld_s[j].lr_atom == DW_OP_addr)
                                (*locdesclist_out)[i]->ld_s[j].lr_number += base_address;
                        }
                    }
                    // we also have to add the CU base address for address ranges, but not for any other relocation.  Weird
                    (*locdesclist_out)[i]->ld_lopc += cu_base_address;
                    (*locdesclist_out)[i]->ld_hipc += cu_base_address;
                }
                //printf("{ %llx-%llx ", (*locdesclist_out)[i]->ld_lopc, (*locdesclist_out)[i]->ld_hipc);
                // dwarf_formexprloc(attr, exprnlen, block_ptr,err)
                //load_section(dbg, locdesclist[i]->ld_section_offset, &elem_loc_expr, &err);
                //process_dwarf_locs((*locdesclist_out)[i]->ld_s, (*locdesclist_out)[i]->ld_cents);
                //printf("}");
            }
            //printf("]\n");
            return 0;
        }
        printf("Attribute does not have a location\n");
    }
    // does not have location attribute or error in getting location data
    return -1;

}

void load_func_from_die(Dwarf_Debug *dbg, Dwarf_Die the_die,
        const char *basename,  uint64_t base_address,uint64_t cu_base_address, bool needs_reloc){
    char* die_name = 0;
    Dwarf_Error err;
    Dwarf_Half tag;
    Dwarf_Attribute* attrs;
    Dwarf_Addr lowpc = 0, highpc = 0;
    Dwarf_Signed attrcount, i;
    Dwarf_Locdesc **locdesclist;
    Dwarf_Signed loccnt;

    int rc = dwarf_diename(the_die, &die_name, &err);
    if (rc == DW_DLV_ERROR){
        die("Error in dwarf_diename\n");
        return;
    }
    else if (rc == DW_DLV_NO_ENTRY)
        return;

    if (dwarf_tag(the_die, &tag, &err) != DW_DLV_OK){
        die("Error in dwarf_tag\n");
        return;
    }

    /* Only interested in subprogram DIEs here */
    if (tag != DW_TAG_subprogram)
        return;

    /* Grab the DIEs attributes for display */
    if (dwarf_attrlist(the_die, &attrs, &attrcount, &err) != DW_DLV_OK)
        die("Error in dwarf_attlist\n");

    bool found_highpc = false;
    bool found_fp_info = false;
    for (i = 0; i < attrcount; ++i) {
        Dwarf_Half attrcode;
        if (dwarf_whatattr(attrs[i], &attrcode, &err) != DW_DLV_OK)
            die("Error in dwarf_whatattr\n");

        /* We only take some of the attributes for display here.
        ** More can be picked with appropriate tag constants.
        */
        if (attrcode == DW_AT_low_pc){
            dwarf_formaddr(attrs[i], &lowpc, 0);
            // address is line of function + 1
            // in order to skip past function prologue

            //die("Error: line %d, address: 0x%llx, function %s\n", j, lowpc_before_prol, die_name);
        }
        else if (attrcode == DW_AT_high_pc) {
            enum Dwarf_Form_Class fc = DW_FORM_CLASS_UNKNOWN;
            Dwarf_Half theform = 0;
            Dwarf_Half directform = 0;
            Dwarf_Half version = 0;
            Dwarf_Half offset_size = 0;
            int wres = 0;

            get_form_values(attrs[i],&theform,&directform);
            wres = dwarf_get_version_of_die(the_die,&version,&offset_size);
            if (wres != DW_DLV_OK) {
                die("Cannot get DIE context version number");
                break;
            }
            fc = dwarf_get_form_class(version,attrcode,offset_size,theform);
            dwarf_formaddr(attrs[i], &highpc, 0);
            if (fc == DW_FORM_CLASS_CONSTANT)
                highpc += lowpc;

            found_highpc = true;
        }
        else if (attrcode == DW_AT_frame_base){
            // get where attribute frame base attribute points
            if (-1 == get_die_loc_info(*dbg, the_die, attrcode, &locdesclist,&loccnt, base_address, cu_base_address, needs_reloc)){
                printf("Was not able to get [%s] location info for it\'s frame pointer\n", die_name);
            }
            else{
                found_fp_info = true;
            }
        }
    }

    if (found_highpc) {
        if (needs_reloc) {
            lowpc += base_address;
            highpc += base_address;
        }
        //functions[std::string(basename)+"!"+die_name] = std::make_pair(lowpc, highpc);
        auto lineToFuncAddress = [lowpc, highpc](LineRange &x){
                // if a line range (we just need to check its lowpc) fits between range of a function
                // we update the LineRange to reflect that the line is in the current function
                if (x.lowpc < highpc && x.lowpc >= lowpc){
                    x.function_addr = lowpc;
                }
        };
        auto lineIsFunctionDef = [lowpc](LineRange &x){
            return x.lowpc == lowpc;
        };
        auto funct_line_it = std::find_if(line_range_list.begin(), line_range_list.end(), lineIsFunctionDef);

        if (funct_line_it != line_range_list.end()){
            fn_start_line_range_list.push_back(*funct_line_it);
            // add the LineRange information for the function to fn_name_to_line_info for later use
            // when resolving dwarf information for .plt functions
            // NOTE: this assumes that all function names are unique.

            fn_name_to_line_info.insert(std::make_pair(std::string(die_name),
                        LineRange(lowpc,
                            highpc,
                            funct_line_it->line_number,
                            funct_line_it->filename,
                            lowpc,
                            funct_line_it->line_off)));

            // now check if current function we are processing is in dynl_functions if so
            // point the dynl_function to this function's line number, filename, and line_off
            for (auto lib_name : processed_libs) {
                if (dynl_functions.find(lib_name + ":plt!" + std::string(die_name)) != dynl_functions.end()){
                    //printf("Trying to match function to %s\n",(lib_name + ":plt!" + std::string(die_name)).c_str());
                    Dwarf_Addr plt_addr = dynl_functions[lib_name + ":plt!" + std::string(die_name)];
                    //printf("Found it at 0x%llx, adding to line_range_list\n", plt_addr);
                    //printf(" found a plt function defintion for %s\n", basename);

                    line_range_list.push_back(LineRange(plt_addr,
                                                        plt_addr,
                                                        funct_line_it->line_number,
                                                        funct_line_it->filename,
                                                        lowpc,
                                                        funct_line_it->line_off));

                }
            }
        }
        else {
            printf("Could not find start of function [%s] in line number table something went wrong\n", die_name);
        }

        // this is if we want the start of the function to be one PAST the line that represents start of function
        // in order to skip past function prologue
        //if (funct_line_it != line_range_list.end()){
        //    ++funct_line_it;
        //    fn_start_line_range_list.push_back(*funct_line_it);
        //}
        std::for_each(line_range_list.begin(), line_range_list.end(), lineToFuncAddress);
        funcaddrs[lowpc] = std::string(basename) + "!" + die_name;
        // now add functions frame pointer locaiton list funct_to_framepointers mapping
        if (found_fp_info){
            funct_to_framepointers[lowpc] = std::make_pair(locdesclist, loccnt);
        }
        else {
            funct_to_framepointers[lowpc] = std::make_pair((Dwarf_Locdesc **)NULL, 0);
        }
    }
    else {
        // we are processing a function that is in the .plt so we skip it because the function
        // is either defined in a library we don't have access to or a library our dwarf processor
        // will process later (or maybe already has!)
        return;
    }
    // Load information about arguments and local variables
    //printf("Loading arguments and variables for %s\n", die_name);
    Dwarf_Die arg_child;
    std::vector<std::string> params;
    std::string argname;
    std::vector<VarInfo> var_list;
    if (dwarf_child(the_die, &arg_child, &err) != DW_DLV_OK) {
        return;
    }
    DwarfVarType *dvt;
    /* Now go over all children DIEs */
    while (arg_child != NULL) {
        if (dwarf_tag(arg_child, &tag, &err) != DW_DLV_OK) {
            die("Error in dwarf_tag\n");
            break;
        }
        switch (tag) {
            /* fall through to default case to get sibling die */
            case DW_TAG_formal_parameter:
                argname = getNameFromDie(arg_child);

                dvt = (DwarfVarType *)malloc(sizeof(DwarfVarType));
                *dvt = {*dbg, arg_child};

                if (-1 == get_die_loc_info(*dbg, arg_child, DW_AT_location, &locdesclist,&loccnt, base_address, cu_base_address, needs_reloc)){
                    // value is likely optimized out, so has no location
                    //printf("Var [%s] has no loc\n", argname.c_str());
                } else {
                    var_list.push_back(VarInfo((void *)dvt,argname,locdesclist,loccnt));
                }
                // doesn't work but if we wanted to keep track of params we
                // could do something like this
                //params.push_back(dvt, argname);
                break;
            /* fall through to default case to get sibling die */
            case DW_TAG_unspecified_parameters:
                //params.push_back("...");
                break;
            /* does NOT fall through to default case to get sibling die because gets child die */
            case DW_TAG_lexical_block:
                /* Check the Lexical block DIE for children */
                {
                    Dwarf_Die tmp_die;
                    rc = dwarf_child(arg_child, &tmp_die, &err);
                    if (rc == DW_DLV_NO_ENTRY) {
                        // no children, so skip to end of loop
                        // and get the sibling die
                        arg_child = NULL;
                        break;
                    }
                    else if (rc == DW_DLV_OK) {
                        arg_child = tmp_die;
                        // skip the dwarf_sibling code()
                        // and go to the top of while loop to collect
                        // dwarf information within the lexical block
                        continue;
                    }
                    // there is not arg_child so set it to null
                    else {
                        arg_child = NULL;
                        continue;
                    }
                }
            case DW_TAG_variable:
                argname = getNameFromDie(arg_child);

                dvt = (DwarfVarType *)malloc(sizeof(DwarfVarType));
                *dvt = {*dbg, arg_child};

                if (-1 == get_die_loc_info(*dbg, arg_child, DW_AT_location, &locdesclist,&loccnt, base_address, cu_base_address, needs_reloc)){
                    // value is likely optimized out, so has no location
                    //printf("Var [%s] has no loc\n", argname.c_str());
                } else {
                    var_list.push_back(VarInfo((void *)dvt, argname, locdesclist, loccnt));
                }
                break;
            case DW_TAG_label:
            default:
                //printf("UNKNOWN tag in function dwarf analysis\n");
                break;
        }
        rc = dwarf_siblingof(*dbg, arg_child, &arg_child, &err);

        if (rc == DW_DLV_ERROR) {
            die("Error getting sibling of DIE\n");
            arg_child = NULL;
        }
        else if (rc == DW_DLV_NO_ENTRY) {
            arg_child = NULL; /* done */
        }
    }
    //funct_to_cu_base[lowpc] = cu_base_address;
    funcvars[lowpc] = var_list;
    //funcparams[lowpc] = boost::algorithm::join(params, ", ");
    //printf(" %s #variables: %lu\n", funcaddrs[lowpc].c_str(), var_list.size());

}

/* Load all function and globar variable info.
*/
bool load_debug_info(Dwarf_Debug *dbg, const char *basename, uint64_t base_address, bool needs_reloc) {
    Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header;
    Dwarf_Half version_stamp, address_size;
    Dwarf_Error err;
    Dwarf_Die no_die = 0, cu_die, child_die;
    int count = 0;
    /* Find compilation unit header */
    while (dwarf_next_cu_header(
                *dbg,
                &cu_header_length,
                &version_stamp,
                &abbrev_offset,
                &address_size,
                &next_cu_header,
                &err) != DW_DLV_NO_ENTRY) {
        /* Expect the CU to have a single sibling - a DIE */
        if (dwarf_siblingof(*dbg, no_die, &cu_die, &err) == DW_DLV_ERROR) {
            die("Error getting sibling of CU\n");
            continue;
        }
        Dwarf_Line *dwarf_lines;
        Dwarf_Signed line_count;

        Dwarf_Addr cu_base_address;
        Dwarf_Attribute cu_loc_attr;
        if (dwarf_attr(cu_die, DW_AT_low_pc, &cu_loc_attr, &err) != DW_DLV_OK){
            //printf("CU did not have  low pc.  Setting to 0 . . .\n");
            cu_base_address=0;
        }
        else{
            dwarf_formaddr(cu_loc_attr, &cu_base_address, 0);
            //printf("CU did have low pc 0x%llx\n", cu_base_address);
        }
        int i;
        if (DW_DLV_OK == dwarf_srclines(cu_die, &dwarf_lines, &line_count, &err)){
            char *filenm_tmp;
            char *filenm_cu;
            if (line_count > 0){
                dwarf_linesrc(dwarf_lines[0], &filenm_tmp, &err);
                filenm_cu = (char *) malloc(strlen(filenm_tmp)+1);
                strcpy(filenm_cu, filenm_tmp);

                for (i = 1; i < line_count; i++){
                    char *filenm_line;
                    filenm_tmp = NULL;
                    Dwarf_Addr upper_bound_addr;
                    Dwarf_Addr lower_bound_addr;
                    Dwarf_Unsigned line_num;
                    Dwarf_Unsigned line_off;
                    dwarf_lineaddr(dwarf_lines[i-1], &lower_bound_addr, &err);
                    dwarf_lineaddr(dwarf_lines[i], &upper_bound_addr, &err);

                    dwarf_lineno(dwarf_lines[i-1], &line_num, &err);
                    dwarf_lineoff_b(dwarf_lines[i-1], &line_off, &err);
                    dwarf_linesrc(dwarf_lines[i-1], &filenm_tmp, &err);
                    if (!filenm_tmp || 0 == strcmp(filenm_tmp, filenm_cu)){
                        filenm_line = filenm_cu;
                    }
                    else {
                        filenm_line = (char *) malloc(strlen(filenm_tmp)+1);
                        strcpy(filenm_line, filenm_tmp);
                    }
                    //std::vector<std::tuple<Dwarf_Addr, Dwarf_Addr, Dwarf_Unsigned, char *, Dwarf_Addr>> line_range_list;
                    if (needs_reloc){
                        line_range_list.push_back(LineRange(base_address+lower_bound_addr,
                                                            base_address+upper_bound_addr,
                                                            line_num, filenm_line, line_off, 0));
                    }
                    else{
                        line_range_list.push_back(LineRange(lower_bound_addr, upper_bound_addr, line_num,
                                                            filenm_line, line_off, 0));
                    }
                    //printf("line no: %lld at addr: 0x%llx\n", line_num, lower_bound_addr);
                }
            }
        }
        else
            printf("Could not get get function line number\n");

        /* Expect the CU DIE to have children */
        if (dwarf_child(cu_die, &child_die, &err) == DW_DLV_ERROR) {
            die("Error getting child of CU DIE\n");
            continue;
        }

        /* Now go over all children DIEs */
        DwarfVarType *dvt;
        while (1) {
            std::string argname;
            int rc;
            Dwarf_Half tag;
            if (dwarf_tag(child_die, &tag, &err) != DW_DLV_OK)
                die("Error in dwarf_tag\n");

            if (tag == DW_TAG_subprogram){
                load_func_from_die(dbg, child_die, basename, base_address, cu_base_address, needs_reloc);
            }
            else if (tag == DW_TAG_variable){

                Dwarf_Locdesc **locdesclist=NULL;
                Dwarf_Signed loccnt;
                argname = getNameFromDie(child_die);
                dvt = (DwarfVarType *)malloc(sizeof(DwarfVarType));
                *dvt = {*dbg, child_die};
                if (-1 == get_die_loc_info(*dbg, child_die, DW_AT_location, &locdesclist,&loccnt, base_address, cu_base_address, needs_reloc)){
                    // value is likely optimized out
                    //printf("Var [%s] has no loc\n", argname.c_str());
                }
                else{
                    global_var_list.push_back(VarInfo((void *)dvt,argname,locdesclist,loccnt));
                }
            }

            rc = dwarf_siblingof(*dbg, child_die, &child_die, &err);

            if (rc == DW_DLV_ERROR) {
                die("Error getting sibling of DIE\n");
                break;
            }
            else if (rc == DW_DLV_NO_ENTRY) {
                break; /* done */
            }
        }
        count ++;
    }
    printf("Processed %d Compilation Units\n", count);
    // sort the line number ranges
    if (count < 1){
         return false;
    }
    std::sort(fn_start_line_range_list.begin(), fn_start_line_range_list.end(), sortRange);
    std::sort(line_range_list.begin(), line_range_list.end(), sortRange);
    printf("Successfully loaded debug symbols for %s\n", basename);
    printf("Number of address range to line mappings: %lu num globals: %lu\n", line_range_list.size(), global_var_list.size());
    return true;
}

bool read_debug_info(const char* dbgfile, const char *basename, uint64_t base_address, bool needs_reloc) {
    Dwarf_Debug *dbg = (Dwarf_Debug *) malloc(sizeof(Dwarf_Debug));
    Dwarf_Error err;
    int fd = -1;
    if ((fd = open(dbgfile, O_RDONLY)) < 0) {
        perror("open");
        return false;
    }

    if (dwarf_init(fd, DW_DLC_READ, 0, 0, dbg, &err) != DW_DLV_OK) {
        fprintf(stderr, "Failed DWARF initialization\n");
        return false;
    }

    if (!load_debug_info(dbg, basename, base_address, needs_reloc)){
        fprintf(stderr, "Failed DWARF loading\n");
        return false;
    }

    /* don't free dbg info anymore
    if (dwarf_finish(dbg, &err) != DW_DLV_OK) {
        fprintf(stderr, "Failed DWARF finalization\n");
        return false;
    }
    */
    //close(fd);
    //std::map<target_ulong, std::pair<Dwarf_Debug, int>> libBaseAddr_to_debugInfo;
    libBaseAddr_to_debugInfo[base_address] = std::make_pair(dbg, fd);
    return true;
}

target_ulong monitored_asid = 0;
unsigned num_libs_known = 0;

// We want to catch all loaded modules, but don't want to
// check every single call. This is a compromise -- check
// every 1000 calls. If we had a callback in OSI for
// on_library_load we could do away with this hack.
int mod_check_count = 0;
#define MOD_CHECK_FREQ 1000

bool correct_asid(CPUState *env) {
    OsiProc *p = get_current_process(env);
    if (monitored_asid == 0) {
        // checking if p is not null because we got a segfault here
        // if p is null return false, not @ correct_asid
        if (!p || (p && p->name && strcmp(p->name, proc_to_monitor) != 0)) {
            //printf("p-name: %s proc-to-monitor: %s\n", p->name, proc_to_monitor);
            return false;
        }
        else {
            monitored_asid = panda_current_asid(env);
        }
    }
    if (monitored_asid != panda_current_asid(env)) {
        return false;
    }
    return true;
}

void on_library_load(CPUState *env, target_ulong pc, char *guest_lib_name, target_ulong base_addr){
    if (!correct_asid(env)) return;
    //sprintf(fname, "%s/%s", debug_path, m->name);
    //printf("Trying to load symbols for %s at %#x.\n", lib_name, base_addr);
    std::string lib = std::string(guest_lib_name);
    std::size_t found = lib.find(guest_debug_path);
    if (found == std::string::npos){
        return;
    }
    //lib.replace(found, found+strlen(guest_debug_path), host_debug_path);
    std::string host_lib = lib.substr(0, found) +
                           host_debug_path +
                           lib.substr(found+strlen(guest_debug_path));
    char *lib_name = strdup(host_lib.c_str());
    printf("Trying to load symbols for %s at 0x%x.\n", lib_name, base_addr);
    printf("access(%s, F_OK): %x\n", lib_name, access(lib_name, F_OK));
    if (access(lib_name, F_OK) == -1) {
        fprintf(stderr, "Couldn't open %s; will not load symbols for it.\n", lib_name);
        return;
    }
    uint64_t elf_base = elf_get_baseaddr(lib_name, basename(lib_name), base_addr);
    bool needs_reloc = elf_base != base_addr;
    if (!read_debug_info(lib_name, basename(lib_name), base_addr, needs_reloc)) {
        fprintf(stderr, "Couldn't load symbols from %s.\n", lib_name);
        return;
    }
    return;
}

void ensure_dbg_initialized(CPUState *env) {
    OsiProc *p = get_current_process(env);
    bool dbg_initialized;
    OsiModules *libs = NULL;
    // Don't check too often
    if (++mod_check_count == MOD_CHECK_FREQ) {
        mod_check_count = 0;
        libs = get_libraries(env, p);
        if (!libs || libs->num == num_libs_known) {
            dbg_initialized = true;
        }
        else {
            num_libs_known = libs->num;
            dbg_initialized = false;
        }
    }
    else {
        dbg_initialized = true;
    }

    if (!dbg_initialized) {
        for (unsigned i = 0; i < libs->num; i++) {
            char fname[260] = {};
            OsiModule *m = &libs->module[i];
            if (!m->name) continue;
            if (mods_seen.find(m->name) != mods_seen.end()) continue;
            mods_seen.insert(m->name);
            //printf("Trying to load symbols for %s at %#x.\n", m->name, m->base);
            sprintf(fname, "%s/%s", host_debug_path, m->name);
            printf("access(%s, F_OK): %x\n", fname, access(fname, F_OK));
            if (access(fname, F_OK) == -1) {
                //fprintf(stderr, "Couldn't open %s; will not load symbols for it.\n", fname);
                continue;
            }
            uint64_t elf_base = elf_get_baseaddr(fname, m->name, m->base);
            bool needs_reloc = elf_base != m->base;
            if (!read_debug_info(fname, m->name, m->base, needs_reloc)) {
                fprintf(stderr, "Couldn't load symbols from %s.\n", fname);
                continue;
            }
        }
        dbg_initialized = true;
        //for (auto &kvp : funcaddrs) {
        //    printf("%#x %s\n", kvp.first, kvp.second.c_str());
        //}
    }
}

target_ulong get_cur_fp(CPUState *env, target_ulong pc){
    if (funct_to_framepointers.find(cur_function) == funct_to_framepointers.end()){
        printf("funct_to_framepointers: could not find fp information for current function\n");
        return -1;
    }
    Dwarf_Locdesc **locdesc = funct_to_framepointers[cur_function].first;
    Dwarf_Signed loc_cnt = funct_to_framepointers[cur_function].second;
    if (loc_cnt == 0 || locdesc == NULL){
        printf("loc_cnt: Could not properly determine fp\n");
        return -1;
    }
    target_ulong fp_loc;
    int i;
    for (i = 0; i < loc_cnt; i++){
       //printf("in loc description for frame pointer:0x%llx-0x%llx\n",locdesc[i]->ld_lopc, locdesc[i]->ld_hipc);
       if (pc >= locdesc[i]->ld_lopc && pc < locdesc[i]->ld_hipc){
            LocType loc_type = execute_stack_op(env,pc, locdesc[i]->ld_s, locdesc[i]->ld_cents, 0, &fp_loc);
            if (loc_type != LocMem){
                printf("loc_type: Could not properly determine fp\n");
                return -1;
            }
            //printf("Found fp at 0x%x\n", fp_loc);
            return fp_loc;
        }
    }
    printf("Not in range: Could not properly determine fp for pc @ 0x" TARGET_FMT_lx "\n", pc);
    return -1;
}

bool dwarf_in_target_code(CPUState *env, target_ulong pc){
    if (!correct_asid(env)) return false;
    auto it = std::lower_bound(line_range_list.begin(), line_range_list.end(), pc, CompareRangeAndPC());
    if (pc < it->lowpc || it == line_range_list.end())
        return false;
    return true;
}

bool translate_callback_dwarf(CPUState *env, target_ulong pc) {
    if (!correct_asid(env)) return false;

    auto it2 = std::lower_bound(line_range_list.begin(), line_range_list.end(), pc, CompareRangeAndPC());
    /*
    // these are just checks to make sure the lower_bound returns the same value as lower_bound
    // after checking this through a recording, I am pretty sure that I have ironed all the kinks out
    // in implementing lower_bound for a vector of ranges
    auto addressInRange = [pc](std::tuple<Dwarf_Addr, Dwarf_Addr, Dwarf_Unsigned, char *, Dwarf_Addr> x) {
        return pc >= std::get<0>(x) && pc < std::get<1>(x);
    };
    auto it = find_if(line_range_list.begin(), line_range_list.end(), addressInRange);
    if (it == line_range_list.end())
        return false;
    */
    /*
    // debugging print statements
    printf(" pc: 0x%x, addr1: 0x%llx-0x%llx addr2: 0x%llx-0x%llx\n", pc,std::get<0>(*it), std::get<1>(*it),
            std::get<0>(*it2), std::get<1>(*it2));
    //printf(" pc: 0x%x, addr2: 0x%llx-0x%llx\n", pc, std::get<0>(*it2), std::get<1>(*it2));
    if (std::get<0>(*it) != std::get<0>(*it2)) {
        auto before_it1 = it - 1;
        auto after_it1 = it + 1;
        auto before_it2 = it2 - 1;
        auto after_it2 = it2 + 1;
        printf(" before linear it: 0x%llx-0x%llx binary search it: 0x%llx-0x%llx\n",
                std::get<0>(*before_it1), std::get<1>(*before_it1),
                std::get<0>(*before_it2), std::get<1>(*before_it2));
        printf(" after linear it: 0x%llx-0x%llx binary search it: 0x%llx-0x%llx\n",
                std::get<0>(*after_it1), std::get<1>(*after_it1),
                std::get<0>(*after_it2), std::get<1>(*after_it2));
        abort();
    }
    */
    // after the call to lower_bound the `pc` should be between it2->lowpc and it2->highpc
    // if it2 == line_range_list.end() we know we definitely didn't find out pc in our line_range_list
    if (pc < it2->lowpc || it2 == line_range_list.end())
        return false;


    return true;

}

void dwarf_log_callsite(CPUState *env, char *file_callee, char *fn_callee, uint64_t lno_callee, bool isCall){
    target_ulong ra = 0;

    int num_received = get_callers(&ra, 1, env);
    if (num_received < 1){
        printf("Error No dwarf information. Could not get callers from callstack plugin\n");
    }

    ra -= 5; // subtract 5 to get address of call instead of return address
    auto it = std::lower_bound(line_range_list.begin(), line_range_list.end(), ra, CompareRangeAndPC());
    if (ra < it->lowpc || it == line_range_list.end()){
        //printf("No DWARF information for callsite 0x%x for current function.\n", ra);
        //printf("Callsite must be in an external library we do not have DWARF information for.\n");
        return;
    }
    Dwarf_Addr call_site_fn = it->function_addr;
    char *file_name = it->filename;
    Dwarf_Unsigned lno = it->line_number;
    std::string funct_name = funcaddrs[call_site_fn];

    //void pri_dwarf_plog(char *file_callee, char *fn_callee, uint64_t lno_callee, char *file_caller, uint64_t lno_caller, bool isCall)
    pri_dwarf_plog(file_callee, fn_callee, lno_callee, file_name, lno, isCall);
    /*
    if (isCall) {
    }
        printf(" CALL: [%s] [0x%llx]-%s(), ln: %4lld, pc @ 0x%x\n",file_name,call_site_fn, funct_name.c_str(),lno,ra);
    else {
        printf(" RET: [%s] [0x%llx]-%s(), ln: %4lld, pc @ 0x%x\n",file_name,call_site_fn, funct_name.c_str(),lno,ra);
    }
    */
    return;
}

void on_call(CPUState *env, target_ulong pc) {
    if (!correct_asid(env)) return;
    auto it = std::lower_bound(line_range_list.begin(), line_range_list.end(), pc, CompareRangeAndPC());
    if (pc < it->lowpc || it == line_range_list.end()){
        /* printf("RET: Could not find line info for 0x%x\n", pc); */
        return;
    }
    cur_function = it->function_addr;
    char *file_name = it->filename;
    std::string funct_name = funcaddrs[cur_function];
    cur_line = it->line_number;
    if (it->lowpc == it->highpc){
        //printf("Calling %s through .plt\n",file_name);
    }
    //printf("CALL: [%s] [0x%llx]-%s(), ln: %4lld, pc @ 0x%x\n",file_name,cur_function, funct_name.c_str(),cur_line,pc);
    dwarf_log_callsite(env, file_name,(char *)funct_name.c_str(), cur_line, true);
    pri_runcb_on_fn_start(env, pc, file_name, funct_name.c_str(), cur_line);

    /*
    if (funcaddrs.find(pc) != funcaddrs.end()){
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
        if (funcaddrs[pc].find(":plt!") == std::string::npos){
            // do something
        }
    }
    */
    // called function is in a dynamic library AND function information
    // hasn't been loaded into funcaddrs and funcparams yet
    //else{
    //    printf("Unknown function at: %x\n", prev_pc);
    //}
}

// pc_func - of the function we are returning from
void on_ret(CPUState *env, target_ulong pc_func) {
    if (!correct_asid(env)) return;
    //printf(" on_ret address: %x\n", func);
    auto it = std::lower_bound(line_range_list.begin(), line_range_list.end(), pc_func, CompareRangeAndPC());
    if (pc_func < it->lowpc || it == line_range_list.end()){
        /* printf("RET: Could not find line info for 0x%x\n", pc_func); */
        return;
    }
    cur_function = it->function_addr;
    char *file_name = it->filename;
    std::string funct_name = funcaddrs[cur_function];
    cur_line = it->line_number;
    //printf("RET: [%s] [0x%llx]-%s(), ln: %4lld, pc @ 0x%x\n",file_name,cur_function, funct_name.c_str(),cur_line,pc_func);
    dwarf_log_callsite(env, file_name,(char *)funct_name.c_str(), cur_line, false);
}

void __livevar_iter(CPUState *env,
        target_ulong pc,
        std::vector<VarInfo> vars,
        liveVarCB f,
        void *args,
        target_ulong fp){
    //printf("size of vars: %ld\n", vars.size());
    for (auto it : vars){
        // skip 40% of variables
        if (rand() % 100 < 40){
            return;
        }
        void *var_type    = it.var_type;
        std::string var_name    = it.var_name;
        Dwarf_Locdesc **locdesc = it.locations;
        Dwarf_Signed loc_cnt    = it.num_locations;
        for (int i=0; i < loc_cnt; i++){
            //printf("var active in range 0x%llx - 0x%llx\n", locdesc[i]->ld_lopc, locdesc[i]->ld_hipc);
            if (pc >= locdesc[i]->ld_lopc && pc <= locdesc[i]->ld_hipc){
                //enum LocType { LocReg, LocMem, LocConst, LocErr };
                target_ulong var_loc;
                //process_dwarf_locs(locdesc[i]->ld_s, locdesc[i]->ld_cents);
                //printf("\n");
                LocType loc = execute_stack_op(env,pc, locdesc[i]->ld_s, locdesc[i]->ld_cents, fp, &var_loc);
                switch (loc){
                    case LocReg:
                        //printf(" VAR %s in REG %d\n", var_name.c_str(), var_loc);
                        break;
                    case LocMem:
                        //printf(" VAR %s in MEM 0x%x\n", var_name.c_str(), var_loc);
                        break;
                    case LocConst:
                        //printf(" VAR %s CONST VAL %d\n", var_name.c_str(), var_loc);
                        break;
                    case LocErr:
                        //printf(" VAR %s - Can\'t handle location information\n", var_name.c_str());
                        break;
                }
                f((void *)var_type, var_name.c_str(),loc, var_loc, args);
            }
        }
    }
    return;
}

// returns 1 if successful find, 0 ow
// will assign found variable to ret_var
int livevar_find(CPUState *env,
        target_ulong pc,
        std::vector<VarInfo> vars,
        liveVarPred pred,
        void *args,
        VarInfo &ret_var){

    target_ulong fp = get_cur_fp(env, pc);
    if (fp == (target_ulong) -1){
        printf("Error: was not able to get the Frame Pointer for the function %s at @ 0x" TARGET_FMT_lx "\n", funcaddrs[cur_function].c_str(), pc);
        return 0;
    }
    for (auto it : vars){
        void *var_type    = it.var_type;
        std::string var_name    = it.var_name;
        Dwarf_Locdesc **locdesc = it.locations;
        Dwarf_Signed loc_cnt    = it.num_locations;
        for (int i=0; i < loc_cnt; i++){
            //printf("var active in range 0x%llx - 0x%llx\n", locdesc[i]->ld_lopc, locdesc[i]->ld_hipc);
            if (pc >= locdesc[i]->ld_lopc && pc <= locdesc[i]->ld_hipc){
                target_ulong var_loc;
                //process_dwarf_locs(locdesc[i]->ld_s, locdesc[i]->ld_cents);
                //printf("\n");
                LocType loc = execute_stack_op(env,pc, locdesc[i]->ld_s, locdesc[i]->ld_cents, fp, &var_loc);
                if (pred(var_type, var_name.c_str(),loc, var_loc, args)){
                    ret_var.var_type = it.var_type;
                    ret_var.var_name = it.var_name;
                    ret_var.locations = it.locations;
                    ret_var.num_locations = it.num_locations;
                    return 1;
                }
            }
        }
    }
    return 0;
}

/********************************************************************
 * end PPPs
******************************************************************** */
int compare_address(void *var_ty, const char *var_nm, LocType loc_t, target_ulong loc, void *query_address){
    switch (loc_t){
        case LocReg:
            break;
        case LocMem:
            if (loc == (*(target_ulong *) query_address) ){
            //if (loc == *query_address) {
                return 1;
            }
            break;
        case LocConst:
            break;
        case LocErr:
            break;
    }
    return 0;
}
void dwarf_get_vma_symbol (CPUState *env, target_ulong pc, target_ulong vma, char ** symbol_name){
    if (!correct_asid(env)) {
        *symbol_name = NULL;
        return;
    }
    target_ulong fn_address;

    auto it = std::lower_bound(line_range_list.begin(), line_range_list.end(), pc, CompareRangeAndPC());
    if (pc < it->lowpc || it == line_range_list.end() ) {
        *symbol_name = NULL;
        return;
    }
    // either get fn_address for local vars by finding
    // function that pc appears in OR use the most recent
    // dwarf_function in callstack
    //fn_address = cur_function
    fn_address = it->function_addr;

    //VarInfo ret_var = VarInfo(NULL, NULL, NULL, 0);
    VarInfo ret_var = VarInfo((void *) NULL, std::string( ""), NULL, 0);
    if (livevar_find(env, pc, funcvars[fn_address], compare_address, (void *) &vma, ret_var)){
        *symbol_name = (char *)ret_var.var_name.c_str();
        return;
    }
    /*
    if (livevar_find(env, pc, global_var_list, compare_address, (void *) &vma, ret_var)){
        *symbol_name = (char *)ret_var.var_name.c_str();
        return;
    }
    */
    *symbol_name = NULL;
    return;
}
void dwarf_get_pc_source_info(CPUState *env, target_ulong pc, SrcInfo *info, int *rc){
    if (!correct_asid(env)) {
        *rc = -1;
        return;
    }
    auto it = std::lower_bound(line_range_list.begin(), line_range_list.end(), pc, CompareRangeAndPC());
    if (pc < it->lowpc || it == line_range_list.end()){
        auto it_dyn = addr_to_dynl_function.find(pc);
        if (it_dyn != addr_to_dynl_function.end()){
            //printf("In a a plt function\n");
            info->filename = NULL;
            info->line_number = 0;
            info->funct_name = it_dyn->second.c_str();
            *rc = 1;
        }
        else {
            *rc = -1;
        }
        return;
    }

    if (it->lowpc == it->highpc){
        //printf("In a a plt function\n");
        *rc = 1;
        return;
    }
    // we are in dwarf-land, so populate info struct
    Dwarf_Addr call_site_fn = it->function_addr;
    info->filename = it->filename;
    info->line_number = it->line_number;
    std::string funct_name = funcaddrs[call_site_fn];
    info->funct_name = funct_name.c_str();
    *rc = 0;
    return;
}
void dwarf_all_livevar_iter(CPUState *env,
        target_ulong pc,
        liveVarCB f,
        void *args){
        //void (*f)(const char *var_ty, const char *var_nm, LocType loc_t, target_ulong loc)){
    if (inExecutableSource){
        target_ulong fp = get_cur_fp(env, pc);
        if (fp == (target_ulong) -1){
            printf("Error: was not able to get the Frame Pointer for the function %s at @ 0x" TARGET_FMT_lx "\n",
                    funcaddrs[cur_function].c_str(), pc);
            return;
        }
        __livevar_iter(env, pc, funcvars[cur_function], f, args, fp);
    }

    // iterating through global vars does not require a frame pointer
    __livevar_iter(env, pc, global_var_list, f, args, 0);
}
void dwarf_funct_livevar_iter(CPUState *env,
        target_ulong pc,
        liveVarCB f,
        void *args){
    //printf("iterating through live vars\n");
    if (inExecutableSource){
        target_ulong fp = get_cur_fp(env, pc);
        if (fp == (target_ulong) -1){
            printf("Error: was not able to get the Frame Pointer for the function %s at @ 0x" TARGET_FMT_lx "\n",
                    funcaddrs[cur_function].c_str(), pc);
            return;
        }
        __livevar_iter(env, pc, funcvars[cur_function], f, args, fp);
    }
}
void dwarf_global_livevar_iter(CPUState *env,
        target_ulong pc,
        liveVarCB f,
        void *args){
    // iterating through global vars does not require a frame pointer
    __livevar_iter(env, pc, global_var_list, f, args, 0);
}
int exec_callback_dwarf(CPUState *env, target_ulong pc) {
    inExecutableSource = false;
    if (!correct_asid(env)) return 0;
    auto it2 = std::lower_bound(line_range_list.begin(), line_range_list.end(), pc, CompareRangeAndPC());
    if (it2 == line_range_list.end() || pc < it2->lowpc)
        return 0;
    inExecutableSource = true;
    if (it2->lowpc == it2->highpc) {
        inExecutableSource = false;
    }
    cur_function = it2->function_addr;
    char *file_name = it2->filename;
    std::string funct_name = funcaddrs[cur_function];
    cur_line = it2->line_number;

    //printf("[%s] [0x%llx]-%s(), ln: %4lld, pc @ 0x%x\n",file_name,cur_function, funct_name.c_str(),cur_line,pc);
    if (funcaddrs.find(cur_function) == funcaddrs.end())
        return 0;
    if (cur_function == 0)
        return 0;
    //printf("[%s] [0x%llx]-%s(), ln: %4lld, pc @ 0x%x\n",file_name,cur_function, funct_name.c_str(),cur_line,pc);
    //__livevar_iter(env, pc, funcvars[cur_function], push_var_if_live);
    //__livevar_iter(env, pc, global_var_list, push_var_if_live);
    //__livevar_iter(env, pc, global_var_list, print_var_if_live);
    if (cur_line != prev_line){
        //printf("[%s] %s(), ln: %4lld, pc @ 0x%x\n",file_name, funct_name.c_str(),cur_line,pc);
        pri_runcb_on_after_line_change(env,pc,prev_file_name,prev_funct_name.c_str(), prev_line);
        pri_runcb_on_before_line_change(env, pc, file_name, funct_name.c_str(), cur_line);
        PPP_RUN_CB(on_pri_dwarf_line_change, env, pc, file_name, funct_name.c_str(), cur_line);

        // reset previous line information
        prev_file_name = file_name;
        prev_funct_name = funct_name;
        prev_line_pc = pc;
        prev_function = cur_function;
        prev_line = cur_line;
    }
    //if (funcaddrs.find(pc) != funcaddrs.end()){
    //    on_call(env, pc);
    //}
    return 0;
}
/********************************************************************
 * end PPPs
******************************************************************** */

uint32_t guest_strncpy(CPUState *env, char *buf, size_t maxlen, target_ulong guest_addr) {
    buf[0] = 0;
    unsigned i;
    for (i=0; i<maxlen; i++) {
        uint8_t c;
        panda_virtual_memory_rw(env, guest_addr+i, &c, 1, 0);
        buf[i] = c;
        if (c==0) {
            break;
        }
    }
    buf[maxlen-1] = 0;
    return i;
}

// get current process before each bb execs
// which will probably help us actually know the current process
int osi_foo(CPUState *env, TranslationBlock *tb) {

    if (panda_in_kernel(env)) {

        OsiProc *p = get_current_process(env);

        //some sanity checks on what we think the current process is
        // this means we didnt find current task
        if (p->offset == 0) return 0;
        // or the name
        if (p->name == 0) return 0;
        // this is just not ok
        if (((int) p->pid) == -1) return 0;
        uint32_t n = strnlen(p->name, 32);
        // name is one char?
        if (n<2) return 0;
        uint32_t np = 0;
        for (uint32_t i=0; i<n; i++) {
            np += (isprint(p->name[i]) != 0);
        }
        // name doesnt consist of solely printable characters
        //        printf ("np=%d n=%d\n", np, n);
        if (np != n) return 0;
        target_ulong asid = panda_current_asid(env);
        if (running_procs.count(asid) == 0) {
            printf ("adding asid=0x%x to running procs.  cmd=[%s]  task=0x%x\n", (unsigned int)  asid, p->name, (unsigned int) p->offset);
        }
        running_procs[asid] = *p;
        proc_changed = proc_diff(current_proc, p);
        if (proc_changed) {
            if (current_proc != NULL) {
                free_osiproc(current_proc);
                current_proc = NULL;
            }
            current_proc = copy_osiproc_g(p, current_proc);
            //printf ("proc changed to [%s]\n", current_proc->name);
        }
        free_osiproc(p);
        // turn this off until next asid change
        bbbexec_check_proc = false;
        if (current_proc != NULL && proc_changed) {
            // if we get here, we have a valid proc in current_proc
            // that is new.  That is, we believe process has changed
            if (current_libs) {
                free_osimodules(current_libs);
            }
            current_libs = get_libraries(env, current_proc);
            if (current_libs) {
                for (unsigned i=0; i<current_libs->num; i++) {
                    OsiModule *m = &(current_libs->module[i]);
                    if (tb->pc >= m->base && tb->pc < (m->base + m->size)) {
                        current_lib = m;
                    }
                }
            }
        }
    }

    return 0;
}


#endif
bool init_plugin(void *self) {
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    panda_arg_list *args = panda_get_args("pri_dwarf");
    guest_debug_path = panda_parse_string(args, "g_debugpath", "dbg");
    host_debug_path = panda_parse_string(args, "h_debugpath", "dbg");
    proc_to_monitor = panda_parse_string(args, "proc", "None");
    // panda plugin plugin includes
    panda_require("callstack_instr");
    panda_require("osi");
    panda_require("loaded");
    panda_require("pri");

    //panda_require("osi_linux");
    // make available the api for
    assert(init_callstack_instr_api());
    assert(init_osi_linux_api());
    assert(init_osi_api());
    assert(init_pri_api());

    panda_enable_precise_pc();
    panda_enable_memcb();
    // we may want to change back to using on_call and on_ret CBs
    PPP_REG_CB("callstack_instr", on_call, on_call);
    PPP_REG_CB("callstack_instr", on_ret, on_ret);
    std::string bin_path;
    struct stat s;
    if (stat(host_debug_path, &s) != 0){
        printf("host_debug path does not exist. exiting . . .\n");
        exit(1);
    }
    // host_debug_path is a dir
    // if debug path doesn't point to a file assume debug path points to an install
    // directory on host machine, so add '/bin/' in order to get the main executable
    if (s.st_mode & S_IFDIR) {
        bin_path = std::string(host_debug_path) + "/bin/" + proc_to_monitor;
    }
    // if debug path actually points to a file, then make host_debug_path the
    // directory that contains the executable
    else if (s.st_mode & S_IFREG) {
        bin_path = std::string(host_debug_path);
        //host_debug_path = dirname(strdup(host_debug_path));
        host_debug_path = dirname(strdup(host_debug_path));
    }
    else {
        printf("Don\'t know what host_debug_path: %s is, but it is not a file or directory\n", host_debug_path);
        exit(1);
    }
    printf("opening debug info for starting binary %s\n", bin_path.c_str());
    // third arg (actual_base address or executable) is 0 because we don't know what it is, but for now
    // assume that it is not pie
    elf_get_baseaddr(bin_path.c_str(), proc_to_monitor, 0);
    if (!read_debug_info(bin_path.c_str(), proc_to_monitor, 0, false)) {
        fprintf(stderr, "Couldn't load symbols from %s.\n", bin_path.c_str());
        return false;
    }

    {
        panda_cb pcb_dwarf;
        pcb_dwarf.before_block_exec = osi_foo;
        panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb_dwarf);
        //pcb_dwarf.virt_mem_write = virt_mem_write;
        //panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb_dwarf);
        //pcb_dwarf.virt_mem_read = virt_mem_read;
        //panda_register_callback(self, PANDA_CB_VIRT_MEM_READ, pcb_dwarf);
        pcb_dwarf.insn_translate = translate_callback_dwarf;
        panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb_dwarf);
        pcb_dwarf.insn_exec = exec_callback_dwarf;
        panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb_dwarf);
    }

    PPP_REG_CB("loaded", on_library_load, on_library_load);
    // contracts we fulfill for pri plugin
    PPP_REG_CB("pri", on_get_pc_source_info, dwarf_get_pc_source_info);
    PPP_REG_CB("pri", on_get_vma_symbol, dwarf_get_vma_symbol);
    PPP_REG_CB("pri", on_all_livevar_iter, dwarf_all_livevar_iter);
    PPP_REG_CB("pri", on_funct_livevar_iter, dwarf_funct_livevar_iter);
    PPP_REG_CB("pri", on_global_livevar_iter, dwarf_global_livevar_iter);
    return true;
#else
    printf("Dwarf plugin not supported on this architecture\n");
    return false;
#endif
}

void uninit_plugin(void *self) { }
