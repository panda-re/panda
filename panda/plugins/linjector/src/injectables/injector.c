#include "include/syscall_x86.h"
#include "include/hypercall.h"
#define MFD_CLOEXEC		0x0001U

int _start(void){
    int pid = syscall_0(__NR_fork);
    if (pid == 0){
        // child process
        int val = 0;
        while(!val){
            hc(HC_STOP, (char*)&val);
            syscall_0(__NR_sched_yield);
        }
        char none = '\0';
        int fd = syscall_2(__NR_memfd_create, (int)&none, MFD_CLOEXEC);
        char buf[512];
        int rlen;
        while ((rlen = hc_rec(HC_WRITE, (char*)&buf,sizeof(buf)/sizeof(buf[0])))>0){
            syscall_3(__NR_write, fd, (int)buf, rlen);
        }
        hc(HC_NEXT_STATE_MACHINE, (char*)0);
        unsigned char execbuf[] = {47, 112, 114, 111, 99, 47, 115, 101, 108, 102, 47, 102, 100, 47, 48, 0};
        execbuf[14] += fd;
        char* argv[] = {(char*)0};
        syscall_3(__NR_execve, (int)execbuf, (int)argv, (int)argv);
    }else{
        // parent process
        int pathname = hc(HC_READ,(char*)pid);
        int argv = hc(HC_READ, (char*) pid);
        int envp = hc(HC_READ, (char*) pid);
        syscall_3(__NR_execve, pathname, argv, envp);
    }
}

        //int pc = hc(HC_READ, (char*)pid);
        //int eax = hc(HC_READ, (char*)pid);
        //int ecx = hc(HC_READ, (char*)pid);
        //int edx = hc(HC_READ, (char*)pid);
        //int ebx = hc(HC_READ, (char*)pid);
        //int esp = hc(HC_READ, (char*)pid);
        //int ebp = hc(HC_READ, (char*)pid);
        //int esi = hc(HC_READ, (char*)pid);
        //int edi = hc(HC_READ, (char*)pid);
        //asm volatile("mov %%eax, %0" : : "r"(eax));
        //asm volatile("mov %%ecx, %0" : : "r"(ecx));
        //asm volatile("mov %%edx, %0" : : "r"(edx));
        //asm volatile("mov %%ebx, %0" : : "r"(ebx));
        //asm volatile("mov %%esi, %0" : : "r"(esi));
        //asm volatile("mov %%edi, %0" : : "r"(edi));
        //asm volatile("mov %%esp, %0" : : "r"(esp));
        //asm volatile("mov %%ebp, %0" : : "r"(ebp));
        ////asm volatile ("jmp *%0" : : "r" (pc));
        //asm volatile ("jmp -2");
        //while(1);