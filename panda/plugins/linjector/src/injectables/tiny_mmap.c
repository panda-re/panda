#include "include/syscall_x86.h"
#include "include/hypercall.h"

// how much memory we give the injector
#define PAGE_SIZE 0x1000

int _start(void){
    void* region = syscall_6(__NR_mmap2, NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANON,-1,0);
    hc(HC_START,(char*)region);
    (*(void(*)()) region)();
}