

#define __STDC_FORMAT_MACROS

#include <algorithm>
#include <string>
#include <iostream>

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

extern "C" {
#include "panda/rr/rr_log.h"
#include "panda/plog.h"

#include "pri/pri_types.h"
#include "pri/pri_ext.h"
#include "pri/pri.h"

#include "cpu.h"
#include "libfi.h"
#include "libfi_int_fns.h"

bool init_plugin(void *);
void uninit_plugin(void *);

void libfi_add_callback(char *libname, char *fnname, int isenter, uint32_t numargs, libfi_cb_t cb);

}

using namespace std;


#if defined(TARGET_I386) && !defined(TARGET_X86_64)

struct LibFICbEntry {
    string libname;
    string fnname;
    bool isenter;
    uint32_t numargs;
    libfi_cb_t callback;    
};

std::vector<LibFICbEntry> libficbes;

enum CallingConv {CC_CDECL, CC_DUNNO};
int calling_convention = CC_CDECL;

#define ESP (((CPUX86State *)env)->regs[R_ESP])

#define MAX_ARGS 16
uint32_t word_size = 0;

// program args
uint64_t *arg=NULL;

static inline void set_word_size() {
    if (word_size == 0) {
        word_size = (((CPUX86State *)first_cpu)->hflags & HF_LMA_MASK) ? 64 : 32;
    }
}

// stolen from phulin's useafter plugin
// Assumes target+host have same endianness.
static inline target_ulong get_word(CPUState *env, target_ulong addr) {
    target_ulong result = 0;
    set_word_size();
    panda_virtual_memory_rw(env, addr, (uint8_t *)&result, word_size, 0);
    return result;
}

// Returns [esp + word_size*offset_number]
static inline target_ulong get_stack(CPUState *env, int offset_number) {
    set_word_size();
    return get_word(env, ESP + word_size * offset_number);
}

void fn_start(CPUState *env, target_ulong pc, const char *file_name, 
              const char *funct_name) {
    printf ("fn start %s\n", funct_name);
    // grab args for this fn if this guy has either enter or exit cb
    for (LibFICbEntry &cbe : libficbes) {
        if (cbe.fnname == funct_name) {
            if (calling_convention == CC_CDECL ) {                
                for (uint32_t i=0; i<cbe.numargs; i++) {
                    arg[i] = (uint64_t) get_stack(env, i+1);
                }
            }
            break;
        }
    }
    for (LibFICbEntry &cbe : libficbes) {
        if (cbe.isenter && cbe.fnname == funct_name) {            
            (*cbe.callback)(env, pc, (uint8_t *) arg);
        }
    }   
}

void fn_return(CPUState *env, target_ulong pc, const char *file_name, 
               const char *funct_name) {
    printf ("fn end %s\n", funct_name);
    for (LibFICbEntry &cbe : libficbes) {
        if (!cbe.isenter && cbe.fnname == funct_name) {
            // args populated by fn_start i hope
            (*cbe.callback)(env, pc, (uint8_t *) arg);
        }           
    }   
}

void libfi_add_callback(char *libname, char *fnname, int isenter, uint32_t numargs, libfi_cb_t cb) {
    LibFICbEntry cbe = {string(libname), string(fnname), (isenter == 1), numargs, cb};
    libficbes.push_back(cbe);
    printf ("addign callback %s %s %d \n", libname, fnname, isenter);
/*
    LibFICbEntry *cbe = (LibFICbEntry *) malloc(sizeof(LibFICbEntry));
    cbe->libname = string(libname);
    cbe->fnname = string(fnname);
    cbe->isenter = (isenter == 1);
    cbe->numargs = numargs;
    cbe->callback = cb;
    libficbes.push_back(*cbe);    
*/
}
#endif 

bool init_plugin(void *self) {
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    printf ("Initializing plugin libfi\n");
    panda_require("pri");
    PPP_REG_CB("pri", on_fn_start, fn_start);
    PPP_REG_CB("pri", on_fn_return, fn_return);
    arg = (uint64_t *) malloc (sizeof(uint64_t) * MAX_ARGS);
#endif
    return true;
}

void uninit_plugin(void *self) {
}

