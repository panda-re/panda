/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Andrew Fasano               fasano@mit.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#include "osi/osi_types.h"
#include "osi/osi_ext.h"


// Only check process name, don't check module names within each process
#define PROCESS_NAME_ONLY

#ifdef TARGET_I386
#ifdef TARGET_X86_64
static const char * const regnames[] = {
  "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
};
#define PC_NAME "rip"
#else
static const char * const regnames[] = {
  "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
  "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"
};
#define PC_NAME "eip"
#endif //i386
#else
#define PC_NAME "error"
#endif

// Note we probably should use TARGET_FMT_lx, but we want to skip leading 0s
// so we'll just cast everything to host (long unsigned int) which should be bigger than guest pointers
#define FMT_STR "%lx"


// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
  bool init_plugin(void *);
  void uninit_plugin(void *);
  void mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, size_t size, uint8_t *buf);

  void mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, size_t size, uint8_t *buf);
  int exec_callback(CPUState *cpu, target_ulong pc);
}

target_ulong *lastregs;
target_ulong lastpc = 0;

#define MEM_BUF_SIZE (1024*8)

char *mem_buffer = NULL; // heap allocated buffer

FILE *result_log;
const char* target = NULL;

bool should_log(CPUState *cpu, target_ulong pc) {
    // our target process or target is NULL
    if (!target) {
      return true;
    }

    if (panda_in_kernel_mode(cpu) || panda_in_kernel_code_linux(cpu)) {
        // target set but we're in kernel mode/code - can't be correct
        return false;
    }

    // get the current process
    OsiProc *process = get_current_process(cpu);
    if (!process) {
        return false;
    }

    // First check the name of the process
    if (0 != strcasecmp(process->name, target)) {
        free_osiproc(process);
        return false;
    }

#ifndef PROCESS_NAME_ONLY
    // Check if we're in the right module

    // load mappings
    GArray * mappings = get_mappings(cpu, process);
    if (mappings == NULL) {
        free_osiproc(process);
        return false;
    }

    // Pull current memory mapping sso we can handle library code properly. For now, we only
    // care about if we're in the main executable section or not.

    // the first module mapped is the main executable itself
    OsiModule *module = &g_array_index(mappings, OsiModule, 0);

    // is the current module the one we're looking for? - this is a bit redundant with the process name check
    if (0 != strcasecmp(module->name, target)) {
        free_osiproc(process);
        g_array_free(mappings, true);
        return false;
    }

    // Are we not in the main executable (i.e., are we in library code?)
    if (pc <= module->base || pc >= (module->base + module->size)) {
        free_osiproc(process);
        g_array_free(mappings, true);
        return false;
    }
    g_array_free(mappings, true);
#endif

    // It's a match - cleanup and return
    free_osiproc(process);
    return true;
}

bool translate_callback(CPUState* cpu, target_ulong pc){
    // call exec_callback whenever should_log returns true
    if (should_log(cpu, pc)) {
        panda_enable_memcb();
        return true;
    }else{
        panda_disable_memcb();
        return false;
    }
}

int exec_callback(CPUState *cpu, target_ulong pc) {
    // Report register delta
    if (unlikely(!should_log(cpu, pc))) {
        panda_disable_memcb();
        return 0;
    }

    //printf("exec cb at " TARGET_FMT_lx ", thingy is %lu\n", pc, strlen(mem_buffer));

    // Determine the index of the last register we'll print (to avoid trailing commas)
    int last_change = -1;
#ifdef TARGET_I386
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    for (int reg_idx=0; reg_idx < CPU_NB_REGS; reg_idx++) {
        if (lastregs[reg_idx] != env->regs[reg_idx]) {
            last_change = reg_idx;
        }
    }
#endif

    // Note the casts here are intentionally a little wrong so we can use %p (assumes host pointer >= guest ptr). That drops all the leading 0s which is a much
    // more compressed format

    if (target == NULL) {
        // New entry - if we're in whole system mode strt with asid, kernel mode
        fprintf(result_log, "asid=0x" TARGET_FMT_lx ",kernel=%d,", panda_current_asid(cpu), panda_in_kernel(cpu));
    }

    // log new PC
    fprintf(result_log, "%s=0x" FMT_STR, PC_NAME, (long unsigned int)pc);

    // Now we started our entry for this line - the rest of the line will either be
    // A) Nothing - no memory accesses to report, no registers changed (other than PC)
    // B) Just memory accesses
    // C) Just registers
    // D) Memory accesses + registers

    // Case A
    if (last_change == -1 && strlen(mem_buffer) == 0) {
        fprintf(result_log, "\n");
        return 0;
    }

    // All other cases need a comma after PC
    fprintf(result_log, ",");



    // Report memory accesses for cases B and D:
    if (strlen(mem_buffer) > 0) {
        // Drop trailing comma in mem_buffer unless case D (in which case we'll keep it)
        if (last_change == -1) {
            mem_buffer[strlen(mem_buffer)-1] = '\0';
        }

        fprintf(result_log, "%s", mem_buffer);
        memset(mem_buffer, 0, MEM_BUF_SIZE);
    }

    // Report registers for cases C and D
#ifdef TARGET_I386
    if (last_change != -1) {
        for (int reg_idx=0; reg_idx < CPU_NB_REGS; reg_idx++) {
            if (lastregs[reg_idx] != env->regs[reg_idx]) {
                // Report delta and update
                lastregs[reg_idx] = env->regs[reg_idx];

                if (reg_idx != last_change) {
                    fprintf(result_log, "%s=0x" FMT_STR ",", regnames[reg_idx], (long unsigned int)lastregs[reg_idx]);
                } else {  // No trailing comma
                    fprintf(result_log,"%s=0x" FMT_STR, regnames[reg_idx], (long unsigned int)lastregs[reg_idx]);
                }
            }
        }
    }

#endif
    fprintf(result_log, "\n");
    return 0;
}

static void mem_callback(CPUState *cpu, target_ulong pc, target_ulong addr,
                         size_t size, uint8_t *buf,
                         bool is_write) {
    if (!should_log(cpu, pc)) {
        panda_disable_memcb();
        return;
    }

    // Note a mem callback is triggered at PC X but we want to report the change for the next PC Y when X != Y
    // to do this, we write these strings into mem_buffer which gets printed later.
    // We keep a trailing , in this buffer which we drop on printing

    // Again, we assume guest poitner size <= host pointer size such that we can use %p isntead of TARGET_FMT_lx
    if (is_write) {
        snprintf(mem_buffer + strlen(mem_buffer), MEM_BUF_SIZE, "mw=" FMT_STR ":", (long unsigned int)addr);
    }else{
        snprintf(mem_buffer + strlen(mem_buffer), MEM_BUF_SIZE, "mr=" FMT_STR ":", (long unsigned int)addr);
    }

    for (unsigned int i = 0; i < size; i++) {
        uint8_t val = ((uint8_t *)buf)[i];
        snprintf(mem_buffer + strlen(mem_buffer), MEM_BUF_SIZE, "%02x", val);
    }

    snprintf(mem_buffer + strlen(mem_buffer), MEM_BUF_SIZE, ",");

    if (strlen(mem_buffer) >= MEM_BUF_SIZE-0x100) {
        printf("[Warning] mem access about to overflow at " TARGET_FMT_lx ": %s. Dumping log now (one entry earlier than it should be)\n", pc,  mem_buffer);
    }

    if (strlen(mem_buffer) >= MEM_BUF_SIZE) {
        fprintf(result_log, "%s", mem_buffer);
        memset(mem_buffer, 0, MEM_BUF_SIZE);
    }

    return;
}
void mem_read_callback(CPUState *cpu, target_ulong pc, target_ulong addr,
                       size_t size, uint8_t *buf) {
    mem_callback(cpu, pc, addr, size, buf, false);
    return;
}

void mem_write_callback(CPUState *cpu, target_ulong pc, target_ulong addr,
                        size_t size, uint8_t *buf) {
    mem_callback(cpu, pc, addr, size, buf, true);
    return;
}

bool init_plugin(void *self) {
    panda_cb pcb;
    const char* filename;
    panda_arg_list *args = panda_get_args("trace");
    filename = panda_parse_string_opt(args, "log",    "trace.txt", "filename of the trace");
    target   = panda_parse_string_opt(args, "target", NULL, "target process to trace");
    result_log = fopen(filename, "w");

    if (!result_log) {
        printf("Couldn't open result_log\n");
        perror("fopen");
        return false;
    }

    if (target) {
        panda_require("osi");
        assert(init_osi_api());
    }

    mem_buffer = (char*) malloc(MEM_BUF_SIZE);
    if (mem_buffer == NULL) {
        perror("malloc");
        return false;
    }


    pcb.insn_translate = translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);

    pcb.insn_exec = exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);

    pcb.virt_mem_after_read = mem_read_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_READ, pcb);

    pcb.virt_mem_after_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_WRITE, pcb);

    // Need this to get precise PC within basic blocks
    panda_enable_precise_pc();
    // Enable memory result_logging
    panda_enable_memcb();

    // Allocate last regs obj
#ifdef TARGET_I386
    // x86 or x86_64
    lastregs = (target_ulong*)malloc(CPU_NB_REGS*sizeof(target_ulong));
#else
    printf("Unsupported architecture\n");
    return false;
#endif
    return true;
}

void uninit_plugin(void *self) {
    fclose(result_log);
    if (mem_buffer != NULL) {
        free(mem_buffer);
    }
}
