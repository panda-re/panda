#ifndef BASE_C_EXAMPLE
#include "/usr/include/i386-linux-gnu/asm/unistd_32.h"
#include "/usr/include/asm-generic/fcntl.h"
#define _SYS_MMAN_H // it's a lie. but it's a good intention
#define __USE_MISC
#include "/usr/include/bits/mman-linux.h"
#endif
#define NULL 0L

#define SYSINL static inline __attribute__((always_inline))

/*
* All the syscall stuff is from musl /arch/i386/syscall_arch.h
*/

#define SYSCALL_INSNS "int $128"

#define SYSCALL_INSNS_12 "xchg %%ebx,%%edx ; " SYSCALL_INSNS " ; xchg %%ebx,%%edx"
#define SYSCALL_INSNS_34 "xchg %%ebx,%%edi ; " SYSCALL_INSNS " ; xchg %%ebx,%%edi"


SYSINL long syscall_0(long n)
{
	unsigned long __ret;
	__asm__ __volatile__ (SYSCALL_INSNS : "=a"(__ret) : "a"(n) : "memory");
	return __ret;
}

SYSINL long syscall_1(long n, long a1)
{
	unsigned long __ret;
	__asm__ __volatile__ (SYSCALL_INSNS_12 : "=a"(__ret) : "a"(n), "d"(a1) : "memory");
	return __ret;
}

SYSINL long syscall_2(long n, long a1, long a2)
{
	unsigned long __ret;
	__asm__ __volatile__ (SYSCALL_INSNS_12 : "=a"(__ret) : "a"(n), "d"(a1), "c"(a2) : "memory");
	return __ret;
}

SYSINL long syscall_3(long n, long a1, long a2, long a3)
{
	unsigned long __ret;
#if !defined(__PIC__) || !defined(BROKEN_EBX_ASM)
	__asm__ __volatile__ (SYSCALL_INSNS : "=a"(__ret) : "a"(n), "b"(a1), "c"(a2), "d"(a3) : "memory");
#else
	__asm__ __volatile__ (SYSCALL_INSNS_34 : "=a"(__ret) : "a"(n), "D"(a1), "c"(a2), "d"(a3) : "memory");
#endif
	return __ret;
}

SYSINL long syscall_4(long n, long a1, long a2, long a3, long a4)
{
	unsigned long __ret;
#if !defined(__PIC__) || !defined(BROKEN_EBX_ASM)
	__asm__ __volatile__ (SYSCALL_INSNS : "=a"(__ret) : "a"(n), "b"(a1), "c"(a2), "d"(a3), "S"(a4) : "memory");
#else
	__asm__ __volatile__ (SYSCALL_INSNS_34 : "=a"(__ret) : "a"(n), "D"(a1), "c"(a2), "d"(a3), "S"(a4) : "memory");
#endif
	return __ret;
}

SYSINL long syscall_5(long n, long a1, long a2, long a3, long a4, long a5)
{
	unsigned long __ret;
#if !defined(__PIC__) || !defined(BROKEN_EBX_ASM)
	__asm__ __volatile__ (SYSCALL_INSNS
		: "=a"(__ret) : "a"(n), "b"(a1), "c"(a2), "d"(a3), "S"(a4), "D"(a5) : "memory");
#else
	__asm__ __volatile__ ("pushl %2 ; push %%ebx ; mov 4(%%esp),%%ebx ; " SYSCALL_INSNS " ; pop %%ebx ; add $4,%%esp"
		: "=a"(__ret) : "a"(n), "g"(a1), "c"(a2), "d"(a3), "S"(a4), "D"(a5) : "memory");
#endif
	return __ret;
}

SYSINL long syscall_6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
	unsigned long __ret;
#if !defined(__PIC__) || !defined(BROKEN_EBX_ASM)
	__asm__ __volatile__ ("pushl %7 ; push %%ebp ; mov 4(%%esp),%%ebp ; " SYSCALL_INSNS " ; pop %%ebp ; add $4,%%esp"
		: "=a"(__ret) : "a"(n), "b"(a1), "c"(a2), "d"(a3), "S"(a4), "D"(a5), "g"(a6) : "memory");
#else
	unsigned long a1a6[2] = { a1, a6 };
	__asm__ __volatile__ ("pushl %1 ; push %%ebx ; push %%ebp ; mov 8(%%esp),%%ebx ; mov 4(%%ebx),%%ebp ; mov (%%ebx),%%ebx ; " SYSCALL_INSNS " ; pop %%ebp ; pop %%ebx ; add $4,%%esp"
		: "=a"(__ret) : "g"(&a1a6), "a"(n), "c"(a2), "d"(a3), "S"(a4), "D"(a5) : "memory");
#endif
	return __ret;
}




static inline void* memset(void *buf, int num, int l){
    char* writer  = (char*) buf;
    void* end = buf + l;
    while ((void*)writer < end){
        *writer = num;
        writer++;
    }
    return buf;
}