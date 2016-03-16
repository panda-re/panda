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

//#include "config.h"
#include "rr_log.h"
#include "qemu-common.h"
#include "cpu.h"
#include "panda_plugin.h"
#include "pandalog.h"
#include "panda_common.h"

#include "../osi/osi_types.h"
#include "../osi/osi_ext.h"

// this provides the fd resolution magic
#include "../osi_linux/osi_linux_ext.h"

#include "../syscalls2/gen_syscalls_ext_typedefs.h"
#include "panda_plugin_plugin.h"

#include "../callstack_instr/callstack_instr.h"

#include "../loaded/loaded.h"

#include "dwarf_util.h"

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

const char *debug_path = NULL;
const char *proc_to_monitor = NULL;
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
void on_call(CPUState *env, target_ulong pc);
void on_library_load(CPUState *env, target_ulong pc, char *lib_name, target_ulong base_addr);
}

#include <vector>
#include <map>
#include <set>
#include <string>
#include <boost/algorithm/string/join.hpp>
#define MAX_FILENAME 256

std::map <target_ulong, OsiProc> running_procs;
std::map<std::string,std::pair<Dwarf_Addr,Dwarf_Addr>> functions;
std::map<Dwarf_Addr,std::string> funcaddrs;
std::map<Dwarf_Addr,std::string> funcaddrs_ret;
std::map<Dwarf_Addr,std::string> funcparams;
std::map<std::string, Dwarf_Addr> dynl_functions;
std::set<std::string> mods_seen;

//std::vector<std::tuple<std::string, std::string, Dwarf_Locdesc**, Dwarf_Signed>> all_variables;
std::map<Dwarf_Addr,std::vector<std::tuple<std::string, std::string, Dwarf_Locdesc**, Dwarf_Signed>>> funcvars;
std::vector<std::tuple<std::string, std::string, Dwarf_Locdesc**, Dwarf_Signed>> global_var_list;
std::map<Dwarf_Addr, std::tuple<std::string, std::string>> addrVarMapping;
std::map<Dwarf_Addr,std::vector<Dwarf_Addr>> funct_to_var_addrs;
std::map<Dwarf_Addr,Dwarf_Addr> lowpc_to_highpc;

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

uint64_t elf_get_baseaddr(const char *fname, const char *basename) {
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
            printf("got .plt base address: %x\n", shdr[i].sh_addr);
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

    load_addr = loaddr;
    printf("load addr: 0x%x\n", load_addr);

    // now add plt functions to global plt function mapping
    if (relplt == NULL || dynsym == NULL || dynstrtable == NULL){
        return load_addr;
    }
    for (i = 0; i < relplt_size; i++){
        //uint32_t f_name_strndx = symtab[ELF32_R_SYM(relplt[i].r_info)].st_name;
        uint32_t f_name_strndx = dynsym[ELF32_R_SYM(relplt[i].r_info)].st_name;
        //printf(" [%d] r_offset: %x, .text location: %x,  sym_name: %s\n", i, relplt[i].r_offset, plt_addr+16*i,  &dynstrtable[f_name_strndx]);
        dynl_functions[std::string(basename) + ":plt!" + std::string(&dynstrtable[f_name_strndx])] = (unsigned long)plt_addr+16*i;
    }
    
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


/*
void enumerate_struct(Dwarf_Debug dbg, Dwarf_Die the_die)
{
    Dwarf_Error err;
    Dwarf_Half tag;
    Dwarf_Attribute* attrs;
    Dwarf_Attribute attr;
    Dwarf_Signed attrcount;
    int i;

}
*/

std::pair<std::string, std::string> getNameAndTypeFromDie(Dwarf_Debug dbg, Dwarf_Die the_die){
//void getNameAndTypeFromDie(Dwarf_Debug dbg, Dwarf_Die the_die, std::vector<std::string> *params){
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

    rc = dwarf_diename(the_die, &die_name, &err);
        
    if (rc == DW_DLV_ERROR) {
        die("Error in dwarf_diename\n");
    }
    // if we can't get the argname, that is ok, we can still get the type of the argument
    // and since we are assuming arguments are pushed on the stack, we can still find it's
    // location by examining the stack pointer
    if (rc != DW_DLV_OK) argname = "?";
    else argname = die_name;

    cur_die = the_die;
    int num_derefs = 0;
    std::string arrays = "";
    int start = 1;
    type_name = "";
    // didn't want to use a do/while loop here, so used this awful looking start variable :/
    while ((tag == DW_TAG_pointer_type  ||
            tag == DW_TAG_typedef       || 
            tag == DW_TAG_array_type || 
            tag == DW_TAG_volatile_type || 
            tag == DW_TAG_const_type)   || start)
    {
        start = 0;
        rc = dwarf_attr (cur_die, DW_AT_type, &type_attr, &err);
        if (rc != DW_DLV_OK) 
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
                        printf("  Couldn't parse struct\n");
                        return std::make_pair(type_name + std::string(num_derefs, '*'), argname);
                        //return;
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
                case DW_TAG_typedef:
                    //printf("  [+] typedef: skipping enumeration\n");
                    //dwarf_attr(type_die, DW_AT_type, &type_attr, &err);
                    //dwarf_global_formref(type_attr, &offset, &err);
                    //dwarf_offdie_b(dbg, offset, 1, &type_die, &err);
                    //dwarf_tag(type_die, &tag, &err);
                    break;
                case DW_TAG_base_type:
                    // hit base_type, do something
                    rc = dwarf_diename(type_die, &die_name, &err);
                    if (rc != DW_DLV_OK) type_name += "?";
                    else type_name += die_name;
                    break;
                case DW_TAG_pointer_type: // increment derefs
                    num_derefs += 1;
                    break;
                case DW_TAG_array_type: // what to do here? just going to default, and continuing to enum die
                    arrays += "[]";
                    break; 
                case DW_TAG_enumeration_type: // what to do here? should just treat it like a struct
                    break; 
                case DW_TAG_union_type: // what to do here? should just treat it like a struct
                    break; 
                case DW_TAG_volatile_type: // what to do here?
                    type_name += "volatile"; 
                    break; 
                case DW_TAG_subroutine_type: // what to do here? just going to default, and continuing to enum die
                    type_name += "func_pointer ";
                    break; 
                case DW_TAG_imported_declaration: // what to do here?
                    break; 
                case DW_TAG_unspecified_parameters: // what to do here?
                    break; 
                case DW_TAG_ptr_to_member_type: // what to do here?
                    break; 
                case DW_TAG_const_type: // what to do here?
                    type_name += "const ";
                    break; 
                case DW_TAG_constant: // what to do here?
                    break; 
                default: // we may want to do something different for the default case
                    printf("Got unknown DW_TAG: 0x%x\n", tag);
                    exit(1);
            }
        }
    } 

    //printf("  Added argument %s, type: %s, numderefs: %d\n", argname.c_str(), type_name.c_str(), num_derefs);
    //params->push_back(type_name + std::string(num_derefs, '*') + " " + argname);
    return std::make_pair(type_name + std::string(num_derefs, '*'), argname + arrays);
}

int get_die_loc_info(Dwarf_Debug dbg, Dwarf_Die the_die, Dwarf_Locdesc ***locdesclist_copy, Dwarf_Signed *loccnt, uint64_t base_address, bool needs_reloc) {
    //printf("Found a variable huah\n");
    Dwarf_Error err;
    Dwarf_Bool hasLocation;
    Dwarf_Attribute locationAttr;
    Dwarf_Locdesc **locdesclist;
    int i, j;

    
    if (dwarf_hasattr(the_die, DW_AT_location, &hasLocation, &err) != DW_DLV_OK)
        die("Error in dwarf attr, for determining existences of location attr\n");
    else if (hasLocation){
        if (dwarf_attr(the_die, DW_AT_location, &locationAttr, &err) != DW_DLV_OK)
            die("Error obtaining location attr\n");
        // dwarf_formexprloc(attr, expr_len, block_ptr, &err);
        else if (dwarf_loclist_n(locationAttr, &locdesclist, loccnt, &err) != DW_DLV_OK)
            die("Error getting loclist\n");
        else {
            *locdesclist_copy = (Dwarf_Locdesc **) malloc(sizeof(Dwarf_Locdesc *)*(*loccnt));
            //printf("Variable locs: %llu [", *loccnt);
            for (i = 0; i < *loccnt; i++){
                // copy data to new malloc locdesc that won't be dealloc'd in dwarf cleanup function
                Dwarf_Locdesc *locdesc_copy = (Dwarf_Locdesc *) malloc(sizeof(Dwarf_Locdesc));
                memcpy(locdesc_copy, locdesclist[i], sizeof(Dwarf_Locdesc));
                Dwarf_Loc *loc_recs = (Dwarf_Loc *) malloc(locdesclist[i]->ld_cents*sizeof(Dwarf_Loc));
                memcpy(loc_recs, locdesclist[i]->ld_s, locdesclist[i]->ld_cents*sizeof(Dwarf_Loc));
                (*locdesclist_copy)[i] = locdesc_copy;
                (*locdesclist_copy)[i]->ld_s = loc_recs;

                // patch lo and hi address in locdesc structure
                // for variable "liveness" - this is a different usage of word live than typical uses
                // live in this context means that the value at the location of the variable
                // represents the actual value of the variable
                if (needs_reloc){
                    // if lo = 0 and hi = 0xffffffff then variable is "live" for total scope of program
                    // if hipc and lopc both equal 0 than object has been optimized out
                    // if hi is 0xffffffff and lo does't equal 0 then this will add base address to hi
                    // im basically assuming that hi will not be 0xffffffff unless the variable is
                    // live for all scope of program
                    if ((Dwarf_Addr) -1 != (*locdesclist_copy)[i]->ld_hipc && 0x0 != (*locdesclist_copy)[i]->ld_lopc){
                        (*locdesclist_copy)[i]->ld_lopc += base_address;
                        (*locdesclist_copy)[i]->ld_hipc += base_address;
                    }
                    for (j = 0; j < (*locdesclist_copy)[i]->ld_cents; j++){
                        if (locdesclist[i]->ld_s[j].lr_atom == DW_OP_addr)
                            locdesclist[i]->ld_s[j].lr_number += base_address;
                    }
                }
                //printf("{ %llx-%llx ", (*locdesclist_copy)[i]->ld_lopc, (*locdesclist_copy)[i]->ld_hipc);
                // dwarf_formexprloc(attr, exprnlen, block_ptr,err)
                //load_section(dbg, locdesclist[i]->ld_section_offset, &elem_loc_expr, &err);
                process_dwarf_locs((*locdesclist_copy)[i]->ld_s, (*locdesclist_copy)[i]->ld_cents);
                //printf("}");
            }
            //printf("]\n");
            return 0;
        }
    }
    // does not have location attribute or error in getting location data
    return -1;

}

void load_func_from_die(Dwarf_Debug dbg, Dwarf_Die the_die,
        const char *basename, uint64_t base_address, bool needs_reloc) {
    char* die_name = 0;
    Dwarf_Error err;
    Dwarf_Half tag;
    Dwarf_Attribute* attrs;
    Dwarf_Addr lowpc = 0, highpc = 0;
    Dwarf_Signed attrcount, i;
    int rc = dwarf_diename(the_die, &die_name, &err);
    if (rc == DW_DLV_ERROR)
        die("Error in dwarf_diename\n");
    else if (rc == DW_DLV_NO_ENTRY)
        return;

    if (dwarf_tag(the_die, &tag, &err) != DW_DLV_OK)
        die("Error in dwarf_tag\n");

    /* Only interested in subprogram DIEs here */
    if (tag != DW_TAG_subprogram)
        return;

    /* Grab the DIEs attributes for display */
    if (dwarf_attrlist(the_die, &attrs, &attrcount, &err) != DW_DLV_OK)
        die("Error in dwarf_attlist\n");

    bool found_highpc = false;
    for (i = 0; i < attrcount; ++i) {
        Dwarf_Half attrcode;
        if (dwarf_whatattr(attrs[i], &attrcode, &err) != DW_DLV_OK)
            die("Error in dwarf_whatattr\n");

        /* We only take some of the attributes for display here.
        ** More can be picked with appropriate tag constants.
        */
        if (attrcode == DW_AT_low_pc)
            dwarf_formaddr(attrs[i], &lowpc, 0);
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
    }

    if (found_highpc) {
        if (needs_reloc) {
            lowpc += base_address;
            highpc += base_address;
        }
        functions[std::string(basename)+"!"+die_name] = std::make_pair(lowpc, highpc);
        funcaddrs[lowpc] = std::string(basename) + "!" + die_name;
        funcaddrs_ret[highpc] = std::string(basename) + "!" + die_name;
        //lowpc_to_highpc[lowpc] = highpc;
    }
    else {
        if (dynl_functions.find(std::string(basename) + ":plt!" + std::string(die_name)) != dynl_functions.end()){
            lowpc = dynl_functions[std::string(basename) + ":plt!" + std::string(die_name)] + base_address;
            //printf(" found a plt function defintion for %s\n", basename);
            funcaddrs[lowpc] = std::string(basename) + ":plt!" + std::string(die_name);
        }
        else {
            //printf("No address for %s in dwarf information or .plt\n", die_name);
        }
    }

    // Load information about arguments
    //printf("Loading arguments for %s\n", die_name);
    Dwarf_Die arg_child;
    std::vector<std::string> params;
    std::pair<std::string, std::string> type_argname;
    std::vector<std::tuple<std::string, std::string, Dwarf_Locdesc**, Dwarf_Signed>> var_list;
    if (dwarf_child(the_die, &arg_child, &err) != DW_DLV_OK) {
        return;
    }
    /* Now go over all children DIEs */
    do {
        if (dwarf_tag(arg_child, &tag, &err) != DW_DLV_OK) {
            die("Error in dwarf_tag\n");
            break;
        }
 
        if (tag == DW_TAG_formal_parameter) {
            // pushes name and type information for paramater into params vector
            //getNameAndTypeFromDie(dbg, arg_child, &params);
            type_argname = getNameAndTypeFromDie(dbg, arg_child);
            params.push_back(type_argname.first + " " + type_argname.second);
        }
        else if (tag == DW_TAG_unspecified_parameters) 
            params.push_back("...");
        else if (tag == DW_TAG_variable){
            Dwarf_Locdesc **locdesclist_copy;
            Dwarf_Signed loccnt;
            type_argname = getNameAndTypeFromDie(dbg, arg_child);
            if (-1 == get_die_loc_info(dbg, arg_child, &locdesclist_copy,&loccnt, base_address, needs_reloc)){
                printf("Var [%s] has no loc\n", type_argname.second.c_str());
            }else {
                var_list.push_back(make_tuple(type_argname.first,type_argname.second,locdesclist_copy,loccnt));
            }
        }

        rc = dwarf_siblingof(dbg, arg_child, &arg_child, &err);

        if (rc == DW_DLV_ERROR) {
            die("Error getting sibling of DIE\n");
            break;
        }
        else if (rc == DW_DLV_NO_ENTRY) {
            break; /* done */
        }
    } while (1);
    funcvars[lowpc] = var_list;
    funcparams[lowpc] = boost::algorithm::join(params, ", ");
    //printf(" %s #variables: %lu\n", funcaddrs[lowpc].c_str(), var_list.size());

}

/* Load all function and globar variable info.
*/
void load_debug_info(Dwarf_Debug dbg, const char *basename, uint64_t base_address, bool needs_reloc) {
    Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header;
    Dwarf_Half version_stamp, address_size;
    Dwarf_Error err;
    Dwarf_Die no_die = 0, cu_die, child_die;

    
    /* Find compilation unit header */
    while (dwarf_next_cu_header(
                dbg,
                &cu_header_length,
                &version_stamp,
                &abbrev_offset,
                &address_size,
                &next_cu_header,
                &err) != DW_DLV_NO_ENTRY) {

        /* Expect the CU to have a single sibling - a DIE */
        if (dwarf_siblingof(dbg, no_die, &cu_die, &err) == DW_DLV_ERROR) {
            die("Error getting sibling of CU\n");
            continue;
        }

        /* Expect the CU DIE to have children */
        if (dwarf_child(cu_die, &child_die, &err) == DW_DLV_ERROR) {
            die("Error getting child of CU DIE\n");
            continue;
        }

        /* Now go over all children DIEs */
        while (1) {
            std::pair<std::string, std::string> type_argname;
            int rc;
            Dwarf_Half tag;
            if (dwarf_tag(child_die, &tag, &err) != DW_DLV_OK)
                die("Error in dwarf_tag\n");

            if (tag == DW_TAG_subprogram)
                load_func_from_die(dbg, child_die, basename, base_address, needs_reloc);
            else if (tag == DW_TAG_variable){

                Dwarf_Locdesc **locdesclist_copy=NULL;
                Dwarf_Signed loccnt;
                type_argname = getNameAndTypeFromDie(dbg, child_die);
                if (-1 == get_die_loc_info(dbg, child_die, &locdesclist_copy,&loccnt, base_address, needs_reloc)){
                    printf("Var [%s] has no loc\n", type_argname.second.c_str());
                }
                else{
                    global_var_list.push_back(make_tuple(type_argname.first,type_argname.second,locdesclist_copy,loccnt));
                    // add var to global addr mapping if it is DW_OP_addr
                    if (locdesclist_copy[0]->ld_s[0].lr_atom == DW_OP_addr){
                        addrVarMapping[locdesclist_copy[0]->ld_s[0].lr_number] = (make_tuple(type_argname.first,type_argname.second));
                    }
                }
            }

            rc = dwarf_siblingof(dbg, child_die, &child_die, &err);

            if (rc == DW_DLV_ERROR) {
                die("Error getting sibling of DIE\n");
                break;
            }
            else if (rc == DW_DLV_NO_ENTRY) {
                break; /* done */
            }
        }
    }
    printf("Successfully loaded debug symbols for %s\n", basename);
}

bool read_debug_info(const char* dbgfile, const char *basename, uint64_t base_address, bool needs_reloc) {
    Dwarf_Debug dbg = 0;
    Dwarf_Error err;
    int fd = -1;
    if ((fd = open(dbgfile, O_RDONLY)) < 0) {
        perror("open");
        return false;
    }
    
    if (dwarf_init(fd, DW_DLC_READ, 0, 0, &dbg, &err) != DW_DLV_OK) {
        fprintf(stderr, "Failed DWARF initialization\n");
        return false;
    }

    load_debug_info(dbg, basename, base_address, needs_reloc);

    if (dwarf_finish(dbg, &err) != DW_DLV_OK) {
        fprintf(stderr, "Failed DWARF finalization\n");
        return false;
    }

    close(fd);
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

void on_library_load(CPUState *env, target_ulong pc, char *lib_name, target_ulong base_addr){
    if (!correct_asid(env)) return;
    //sprintf(fname, "%s/%s", debug_path, m->name);
    //printf("Trying to load symbols for %s at %#x.\n", lib_name, base_addr);
    printf("Trying to load symbols for %s at 0x%x.\n", lib_name, base_addr);
    printf("access(%s, F_OK): %x\n", lib_name, access(lib_name, F_OK));
    if (access(lib_name, F_OK) == -1) {
        fprintf(stderr, "Couldn't open %s; will not load symbols for it.\n", lib_name);
        return;
    }
    uint64_t elf_base = elf_get_baseaddr(lib_name, basename(lib_name));
    bool needs_reloc = elf_base != base_addr;
    if (!read_debug_info(lib_name, basename(lib_name), base_addr, needs_reloc)) {
        fprintf(stderr, "Couldn't load symbols from %s.\n", lib_name);
        return; 
    }
    return;
    //for (auto &kvp : funcaddrs) {
    //    printf("%#x %s\n", kvp.first, kvp.second.c_str());
    //}
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
            sprintf(fname, "%s/%s", debug_path, m->name);
            printf("access(%s, F_OK): %x\n", fname, access(fname, F_OK));
            if (access(fname, F_OK) == -1) {
                //fprintf(stderr, "Couldn't open %s; will not load symbols for it.\n", fname);
                continue;
            }
            uint64_t elf_base = elf_get_baseaddr(fname, m->name);
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

void add_var_if_live(CPUState *env, target_ulong pc, std::string var_type, std::string var_name, Dwarf_Locdesc **locdesc, Dwarf_Signed loc_cnt){
    int i;
    if (funct_to_var_addrs.find(pc) == funct_to_var_addrs.end()){
        funct_to_var_addrs[pc] = std::vector<Dwarf_Addr> ();
    }
    for (i=0; i < loc_cnt; i++){
        //if (pc >= locdesc[i]->ld_lopc && pc <= locdesc[i]->ld_hipc && locdesc[i]->ld_hipc != 0xffffffff && locdesc[i]->ld_lopc != 0){
       if (pc >= locdesc[i]->ld_lopc && pc <= locdesc[i]->ld_hipc){
            target_ulong var_loc = execute_stack_op(env,pc, locdesc[i]->ld_s, locdesc[i]->ld_cents, ESP+4);
            //printf(" Adding VAR live range: %llx - %llx: var <%s %s>", locdesc[i]->ld_lopc,locdesc[i]->ld_hipc,var_type.c_str(), var_name.c_str());
            // prints the locexpr for a loc_list
            addrVarMapping[var_loc] = make_tuple(var_type, var_name);
            funct_to_var_addrs[pc].push_back(var_loc);
            //printf (" {");
            //process_dwarf_locs(locdesc[i]->ld_s, locdesc[i]->ld_cents);
            //printf ("}");
            //printf(" @ 0x%x\n", var_loc);
            break;
        } 
    }
}

void update_live_vars(CPUState *env, target_ulong pc){
    //std::vector<std::tuple<std::string, std::string, Dwarf_Locdesc**, Dwarf_Signed>>::iterator it;
    Dwarf_Locdesc **locdesc;
    Dwarf_Signed loc_cnt;
    std::string var_type, var_name;
    // frame ptr is basically ebp + 4, but b/c of unknown magic and where we are in function prologue
    // ESP+4 is actual value of of what will be the functions frame pointer 
    //printf(" Frame ptr: 0x%x\n", ESP + 4);
    // int array -28 int ref -32 local_int -36
    auto it = funcvars[pc].begin();
    for (; it != funcvars[pc].end(); ++it){
        var_type = std::get<0>(*it);
        var_name = std::get<1>(*it);
        locdesc = std::get<2>(*it);
        loc_cnt = std::get<3>(*it);
        add_var_if_live(env, pc, var_type, var_name, locdesc, loc_cnt);
    }
}

void on_call(CPUState *env, target_ulong pc) {
    if (!correct_asid(env)) return;
    //ensure_dbg_initialized(env);
    
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
        //if (funcaddrs[pc].find(":plt!") == std::string::npos && lowpc_to_highpc.find(pc) != lowpc_to_highpc.end()){
        if (funcaddrs[pc].find(":plt!") == std::string::npos){
            update_live_vars(env, pc);
        }
    }
    // called function is in a dynamic library AND function information
    // hasn't been loaded into funcaddrs and funcparams yet
    //else{
    //    printf("Unknown function at: %x\n", prev_pc);
    //}
}

void on_ret(CPUState *env, target_ulong func) {
    if (funcaddrs.find(func) != funcaddrs.end()){
        //printf("Returning from function: %s\n", funcaddrs[func].c_str());
        for(auto it = funct_to_var_addrs[func].begin(); it != funct_to_var_addrs[func].end(); it++){
            addrVarMapping.erase(*it);
        }
    }
    //printf("Call to " TARGET_FMT_lx "\n", pc);
}



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


int virt_mem_write(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf){
    if (!correct_asid(env)) return 0;
    if (addrVarMapping.find(addr) != addrVarMapping.end()){
        std::string var_type = std::get<0>(addrVarMapping[addr]);
        std::string var_name = std::get<1>(addrVarMapping[addr]);
        printf("Virtual write to addr: 0x%x.  Var %s %s\n", addr, var_type.c_str(), var_name.c_str()); 
    }
    return 0;
}
int virt_mem_read(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf){
    if (!correct_asid(env)) return 0;
    if (addrVarMapping.find(addr) != addrVarMapping.end()){
        std::string var_type = std::get<0>(addrVarMapping[addr]);
        std::string var_name = std::get<1>(addrVarMapping[addr]);
        printf("Virtual read to addr: 0x%x.  Var %s %s\n", addr, var_type.c_str(), var_name.c_str()); 
    }
    return 0;
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
    }
    
    return 0;
}
#endif
bool init_plugin(void *self) {
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    panda_arg_list *args = panda_get_args("dwarf");
    debug_path = panda_parse_string(args, "debugpath", "dbg");
    proc_to_monitor = panda_parse_string(args, "proc", "None");
    panda_require("callstack_instr");
    panda_require("osi_linux");
    assert(init_osi_linux_api());
    panda_require("osi");
    assert(init_osi_api());
    panda_require("loaded");

    panda_enable_precise_pc();
    panda_enable_memcb();
    
    PPP_REG_CB("callstack_instr", on_call, on_call);
    PPP_REG_CB("callstack_instr", on_ret, on_ret);
    std::string bin_path = std::string(debug_path) + "/" + proc_to_monitor;
    printf("opening debug info for starting binary %s\n", bin_path.c_str());
    elf_get_baseaddr(bin_path.c_str(), proc_to_monitor);
    if (!read_debug_info(bin_path.c_str(), proc_to_monitor, 0, false)) {
        fprintf(stderr, "Couldn't load symbols from %s.\n", bin_path.c_str());
        return false; 
    }
    
    {
        panda_cb pcb;
        pcb.before_block_exec = osi_foo;
        panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
        pcb.virt_mem_write = virt_mem_write;
        panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);
        pcb.virt_mem_read = virt_mem_read;
        panda_register_callback(self, PANDA_CB_VIRT_MEM_READ, pcb);
    }
    
    PPP_REG_CB("loaded", on_library_load, on_library_load);
    return true;
#else
    printf("Dwarf plugin not supported on this architecture\n");
    return false;
#endif
}

void uninit_plugin(void *self) { }
