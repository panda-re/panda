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

/*
 * Relies on taint and osi.  Will not work without tainted_instructions.
 * PANDA args: -panda 'taint:tainted_instructions=1;osi;win7x86intro;ida_taint'
 *
 * XXX: Only tested for Windows 7
 */

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

// Windows 7 offsets stolen from win7x86intro
#define EPROC_PEB_OFF           0x1a8 // _EPROCESS.Peb
#define PEB_IMAGE_BASE_ADDRESS  0x8   // _PEB.ImageBaseAddress (Reserved3[1])

// Size of a guest pointer. Note that this can't just be target_ulong since
// a 32-bit OS will run on x86_64-softmmu
#define PTR uint32_t

extern "C" {

#include "panda_common.h"
#include "panda_plugin.h"
#include "panda_plugin_plugin.h"

#include "../osi/osi_types.h"
#include "../osi/osi_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);

}

#include "../taint/taint_processor.h"

FILE *jsonFile = NULL;
bool firstCall = true;
uint64_t asid_before = 0;
OsiProc *current_process = NULL;
CPUState *tempEnv = NULL;
target_ulong pc, cs_base;
int flags;

int before_block_exec(CPUState *env, TranslationBlock *tb){
    current_process = get_current_process(env);
    tempEnv = env;
    cs_base = tb->cs_base;
    return 0;
}

void taint_on_tainted_instruction(Shad *shad){
    // Get EPROCESS->PEB->ImageBaseAddress
    PTR eproc = current_process->offset;
    PTR peb = -1;
    PTR current_process_base = -1;
    panda_virtual_memory_rw(tempEnv, eproc+EPROC_PEB_OFF, (uint8_t *)&peb,
        sizeof(PTR), false);
    assert(peb != (PTR)-1);
    //printf("Current process: %s\n", current_process->name);
    //printf("PEB: 0x%x\n", peb);
    panda_virtual_memory_rw(tempEnv, peb+PEB_IMAGE_BASE_ADDRESS,
        (uint8_t *)&current_process_base, sizeof(PTR), false);
    assert(current_process_base != (PTR)-1);
    //printf("Base address: 0x%x\n", current_process_base);
    //printf("cs_base: 0x%x\n", cs_base);

    if (!firstCall){
        fprintf(jsonFile, ",\n");
    }
    else {
        firstCall = false;
    }
    fprintf(jsonFile, "\t{\n");
    fprintf(jsonFile, "\t\t\"asid\" : " TARGET_FMT_ld ",\n",
        current_process->asid);
    fprintf(jsonFile, "\t\t\"pid\" : " TARGET_FMT_ld ",\n",
        current_process->pid);
    fprintf(jsonFile, "\t\t\"process_name\" : \"%s\",\n", current_process->name);
    //offset is EPROCESS. need EPROCESS->PEB->ImageBaseAddress
    //http://www.nirsoft.net/kernel_struct/vista/PEB.html
    fprintf(jsonFile, "\t\t\"virtual_program_base_address\" : %u,\n",
        current_process_base);
    fprintf(jsonFile, "\t\t\"virtual_program_address\" : %lu\n",
        shad->pc - cs_base);
    fprintf(jsonFile, "\t}");
    fflush(jsonFile);
}

bool init_plugin(void *self) {    

    printf("Initializing plugin ida_taint\n");

    // this sets up OS introspection API
    bool x = init_osi_api();  
    assert(x == true);
    
    panda_cb pcb;    
    
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    PPP_REG_CB("taint", on_tainted_instruction, taint_on_tainted_instruction);

    jsonFile = fopen("ida_taint.json", "w");
    fprintf(jsonFile, "[\n");

    return true;
}

void uninit_plugin(void *self) {
    fprintf(jsonFile, "\n]\n");
    fclose(jsonFile);
}

