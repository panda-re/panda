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

extern "C" {

#include "config.h"
#include "qemu-common.h"

#include "panda_common.h"
#include "panda_plugin.h"

}



// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}


const char *kernel_filename = NULL;
bool blit_kernel_done = false;
target_ulong base_addr;
target_ulong entry_addr;


static bool blit_kernel(CPUState *env, TranslationBlock *tb) {
                                             
#if defined(TARGET_I386) 

    if (!blit_kernel_done) {
        printf ("blitting kernel & setting entry\n");
        struct stat s;
        stat(kernel_filename, &s);
        uint8_t *kernel = (uint8_t *) malloc(s.st_size);
        FILE *fp = fopen(kernel_filename, "r");
        fread(kernel, 1, s.st_size, fp);        
        cpu_physical_memory_rw(base_addr, kernel, s.st_size, 1);    
        env->segs[R_CS].base = 0;
        env->eip = entry_addr;
        tb->pc = entry_addr;
        env->hflags |= HF_CS32_MASK;
        blit_kernel_done = true;    
        return true;
    }
    return false;

#endif

}


bool init_plugin(void *self) {

    panda_arg_list *args;

    args = panda_get_args("rehosting");
    kernel_filename = panda_parse_string(args, "kernel", "");
    assert (kernel_filename != NULL);
    assert (strlen(kernel_filename) > 0);
    // this is where we will blit the kernel into memory
    const char *base_addr_str = panda_parse_string(args, "base", "");
    if (strnlen(base_addr_str,10) != 0) {
        base_addr = strtoul(base_addr_str, NULL, 16);
    }
    // and this is the entry point
    const char *entry_addr_str = panda_parse_string(args, "entry", "");
    if (strnlen(entry_addr_str,10) != 0) {
        entry_addr = strtoul(entry_addr_str, NULL, 16);
    }

    printf ("rehosting: kernel=[%s]\n", kernel_filename);
    printf ("rehosting: base=0x%x entry=0x%x\n", base_addr, entry_addr);    

#if defined(TARGET_I386) 
    panda_cb pcb;
    pcb.before_block_exec_invalidate_opt = blit_kernel;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, pcb);
    return true;
#else
    return false;
#endif
}

void uninit_plugin(void *self) {
}
