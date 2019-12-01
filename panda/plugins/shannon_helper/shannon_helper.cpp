
#include "shannon_helper.h"
#include <map>

typedef void (*log_fn)(CPUState *cpu, target_ulong pc);
typedef std::map<target_ulong, log_fn> function_map;

void nop(CPUState *cpu, target_ulong pc){
    printf("i was called: %x\n", pc);
}



void sz_putchar(CPUState *cpu, target_ulong pc)
{
    printf("in putchar\n");
    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
    printf("%c", env->regs[0]);

}

function_map logging_callbacks;

//void log_format_buf(cpu, pc)
//{
    //uint32_t log_obj_p, argv_p;
    //uint8_t log_obj[10];
       
       


    //panda_virtual_memory_rw(cpu, read, (uint8_t *) &log_obj, 10, 0);



    ////vfprintf
//}

void on_call_shannon_cb(CPUState *cpu, target_ulong pc){
    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
    uint32_t r0 = env->regs[0];
    uint32_t r1 = env->regs[1];
    uint32_t r2 = env->regs[2];
    //printf("There was a call\n");
    if ( logging_callbacks.find(pc) != logging_callbacks.end() ) {
        logging_callbacks.at(pc)(cpu, pc);
    }

}






bool init_plugin(void *self) {
    //panda_cb pcb;


    panda_require("callstack_instr");
    if (!init_callstack_instr_api())
        return false;

    PPP_REG_CB("callstack_instr", on_call, on_call_shannon_cb);

    logging_callbacks[0x4054f398] = nop; // log_fatal_error_file_line
    logging_callbacks[0x405489ae] = nop; // log_printf
    logging_callbacks[0x40c71964] = nop; // log_error_buf"
    logging_callbacks[0x4054d660] = nop; // log_format_buf
    logging_callbacks[0x40549130] = nop; // log_printf_debug
    logging_callbacks[0x40cb8f5c] = nop; // log_printf_stage
    logging_callbacks[0x40b3ae60] = sz_putchar;



    return true;
}

void uninit_plugin(void *self) { }
