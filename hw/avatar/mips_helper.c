#include "qemu/osdep.h"
#include "hw/mips/cpudevs.h"
#include "target/mips/cpu.h"

/*  This function gets the currently known PC of CPU 0. Will probably need
 *  rework once we support multiprocessing */
uint64_t get_current_pc(void){
    MIPSCPU *cpu = MIPS_CPU(qemu_get_cpu(0));
    return cpu->env.active_tc.PC;
}

