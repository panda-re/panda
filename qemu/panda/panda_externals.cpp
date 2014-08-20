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

extern "C" {
#include "config.h"
#include "qemu-common.h"
}

#ifdef CONFIG_LLVM

extern CPUState *env;

#include "panda_externals.h"

// Get location of env, if needed in PANDA plugins
void *get_env(void){
    return &env;
}

#endif
