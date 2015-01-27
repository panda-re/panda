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
#include "config.h"
#include "qemu-common.h"
#include "monitor.h"
#include "cpu.h"
#include "disas.h"

#include "panda_plugin.h"

#ifdef CONFIG_ANDROID
// definitions for BEFORE_LOADVM handler
#include "hw/goldfish_device.h"
#include "hw/goldfish_nand.h"
#include "hw/goldfish_mmc.h"
#endif

// This is a C file, so we don't need "extern C"
#include "sample_int_fns.h"

#include <stdio.h>
#include <stdlib.h>

int after_block_callback(CPUState *env, TranslationBlock *tb, TranslationBlock *next_tb);
int before_block_callback(CPUState *env, TranslationBlock *tb);
int guest_hypercall_callback(CPUState *env);
bool translate_callback(CPUState *env, target_ulong pc);
int exec_callback(CPUState *env, target_ulong pc);
int monitor_callback(Monitor *mon, const char *cmd);
int before_loadvm_callback(void);

bool init_plugin(void *);
void uninit_plugin(void *);

FILE *plugin_log;

int guest_hypercall_callback(CPUState *env) {
#ifdef TARGET_I386
    if(env->regs[R_EAX] == 0xdeadbeef) printf("Hypercall called!\n");
#endif
    return 1;
}

int before_block_callback(CPUState *env, TranslationBlock *tb) {
    fprintf(plugin_log, "Next TB: " TARGET_FMT_lx 
#ifdef TARGET_I386
        ", CR3=" TARGET_FMT_lx
#endif
         "%s\n", tb->pc,
#ifdef TARGET_I386
        env->cr[3],
#endif
        "");
    return 0;
}

int after_block_callback(CPUState *env, TranslationBlock *tb, TranslationBlock *next_tb) {
    fprintf(plugin_log, "After TB " TARGET_FMT_lx 
#ifdef TARGET_I386
        ", CR3=" TARGET_FMT_lx
#endif
        " next TB: " TARGET_FMT_lx "\n", tb->pc,
#ifdef TARGET_I386
        env->cr[3],
#endif
        next_tb ? next_tb->pc : 0);
    return 1;
}

// Monitor callback. This gets a string that you can then parse for
// commands. Could do something more complex here, e.g. getopt.
int monitor_callback(Monitor *mon, const char *cmd) {
#ifdef CONFIG_SOFTMMU
    char *cmd_work = g_strdup(cmd);
    char *word;
    word = strtok(cmd_work, " ");
    do {
        if (strncmp("help", word, 4) == 0) {
            monitor_printf(mon,
                "sample plugin help:\n"
                "  sample_foo: do the foo action\n"
            );
        }
        else if (strncmp("sample_foo", word, 10) == 0) {
            printf("Doing the foo action\n");
            monitor_printf(mon, "I did the foo action!\n");
        }
    } while((word = strtok(NULL, " ")) != NULL);
    g_free(cmd_work);
#endif
    return 1;
}

// We're going to log all user instructions
bool translate_callback(CPUState *env, target_ulong pc) {
    // We have access to env here, so we could choose to
    // read the bytes and do something fancy with the insn
    return pc < 0x80000000;
}

int exec_callback(CPUState *env, target_ulong pc) {
    printf("User insn 0x" TARGET_FMT_lx " executed.\n", pc);
    return 1;
}

#ifdef CONFIG_ANDROID

/* For interposing on loadvm, we need an exact copy of the struct used 
 * by the device for serialization. In this case, we are capturing the
 * state of the goldfish_nand and goldfish_mmc devices, which use structs
 * defined in header files */
GoldfishNandDevice __GoldfishNandDevice; //store NAND state here
GoldfishMmcDevice  __GoldfishMmcDevice;  //store MMC state here
int before_loadvm_callback(void){
  // register ourselves as the loadvm handler for mmc and nand!!
  // NOTE: this example assumes one instance of each of the devices of interest.
  // If there are more, take care to handle each instance.
  struct DeviceInfo *info;
  const struct VMStateDescription* nand_vmsd = NULL, *mmc_vmsd = NULL;

  /* First, find the VMSDs for the existing devices.
     Device initialization must have already occured for the list to be populated,
     and the device must be present.
     Devices that have explicit load and save functions instead of a declarative VMSD
     still end up having a VMSD, so this should work in all cases.
     
     Look up the device by it's string ID.*/
  for (info = device_info_list; info != NULL; info = info->next) {
    // the fields are name, fw_name, and alias
    if(info->name && 0 == strncmp(info->name, "goldfish_nand", strlen("goldfish_nand"))){
      nand_vmsd = info->vmsd;
    }else if (info->name && 0 == strncmp(info->name, "goldfish_mmc", strlen("goldfish_mmc"))){
      mmc_vmsd = info->vmsd;
    }
  }

  if(!nand_vmsd || !mmc_vmsd){
    fprintf(stderr, "example: Failed to find VMSD for NAND or MMC\n");
    exit(1);
  }

  // Remove all existing handlers for this device.
  vmstate_unregister_all(nand_vmsd);
  vmstate_unregister_all(mmc_vmsd);

  // Re-register handlers, using our structs as the location to dump state to.
  // If there are multiple copies of a device, make sure to register multiple times,
  // and use separate copies of the struct for any data you want to keep.
  vmstate_register(NULL,0,nand_vmsd,&__GoldfishNandDevice);
  vmstate_register(NULL,0,mmc_vmsd,&__GoldfishMmcDevice);

  return 0;
}

#endif // CONFIG_ANDROID

int sample_function(CPUState *env){
    printf("sample was passed a cpustate\n");
    return 0;
}

int other_sample_function(CPUState *env, int foo){
    printf("other was passed a cpustate and paramater %#X\n", foo);
    return 1;
}


panda_arg_list *args;

bool init_plugin(void *self) {
    panda_cb pcb;

    int i;
    char *tblog_filename = NULL;
    args = panda_get_args("sample");
    if (args != NULL) {
        for (i = 0; i < args->nargs; i++) {
            // Format is sample:file=<file>
            if (0 == strncmp(args->list[i].key, "file", 4)) {
                tblog_filename = args->list[i].value;
            }
            else if (0 == strncmp(args->list[i].key, "easter", 9)) {
                // Second parameter just to show how it's done
                if (0 == strncmp(args->list[i].value, "egg", 3)) {
                    printf(
                        "\n"
                        "    _____    \n"
                        "  .'     '.  \n"
                        " /         \\\n"
                        "Y           Y\n"
                        "|v^v^v^v^v^v|\n"
                        "|===========|\n"
                        "|v^v^v^v^v^v|\n"
                        "Y           Y\n"
                        " \\         /\n"
                        "  '._____.'  \n");
                }
            }
        }
    }

    if (!tblog_filename) {
        fprintf(stderr, "Plugin 'sample' needs argument: -panda-arg sample:file=<file>\n");
        return false;
    }

    plugin_log = fopen(tblog_filename, "w");    
    if(!plugin_log) return false;

    // In general you should always register your callbacks last, because
    // if you return false your plugin will be unloaded and there may be stale
    // pointers hanging around.
    pcb.guest_hypercall = guest_hypercall_callback;
    panda_register_callback(self, PANDA_CB_GUEST_HYPERCALL, pcb);
    pcb.after_block_exec = after_block_callback;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
    pcb.before_block_exec = before_block_callback;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    pcb.monitor = monitor_callback;
    panda_register_callback(self, PANDA_CB_MONITOR, pcb);
    pcb.insn_translate = translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    pcb.insn_exec = exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
#ifdef CONFIG_ANDROID
    pcb.before_loadvm = before_loadvm_callback;
    panda_register_callback(self, PANDA_CB_BEFORE_REPLAY_LOADVM, pcb);
#endif

    return true;
}

void uninit_plugin(void *self) {
    printf("Unloading sample plugin.\n");
    panda_free_args(args);
    fflush(plugin_log);
    fclose(plugin_log);
}
