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
#include "DroidScope/DS_Init.h"
#include "panda_plugin.h"
    
    bool init_plugin(void *self);
    void uninit_plugin(void *self);
}

extern "C" {
bool init_plugin(void *self){
    DS_init();
    return true;
}

void uninit_plugin(void *self){
    DS_close();
}

}

