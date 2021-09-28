// stolen from recctrl.h; modified to make more generic
#include "hypercall_constants.h"


#if defined(__x86_64__) || defined(__i386__)
static inline __attribute__((always_inline)) int hc_rec(hc_cmd action, char *s, int len) {
    int eax = HC_MAGIC;
    int ret = HC_ERROR;

    asm __volatile__(
	"mov %1, %%eax \t\n\
     mov %2, %%ebx \t\n\
     mov %3, %%ecx \t\n\
     mov %4, %%edx \t\n\
     cpuid \t\n\
     mov %%eax, %0 \t\n\
    "
	: "=g"(ret) /* output operand */
	: "g" (eax), "g" (action), "g" (s), "g" (len)/* input operands */
	: "eax", "ebx", "ecx", "edx" /* clobbered registers */
    );

    return ret;
}
static inline __attribute__((always_inline)) int hc(hc_cmd action, char *s) {
    int eax = HC_MAGIC;
    int ret = HC_ERROR;

    asm __volatile__(
	"mov %1, %%eax \t\n\
     mov %2, %%ebx \t\n\
     mov %3, %%ecx \t\n\
     cpuid \t\n\
     mov %%eax, %0 \t\n\
    "
	: "=g"(ret) /* output operand */
	: "g" (eax), "g" (action), "g" (s) /* input operands */
	: "eax", "ebx", "ecx", "edx" /* clobbered registers */
    );

    return ret;
}
#elif defined(__arm__)
static inline __attribute__((always_inline)) int hc(hc_cmd action, char *s) {
    unsigned long r0 = HC_MAGIC;
    int ret = HC_ERROR;

    asm __volatile__(
    "push {r0-r4} \t\n\
     ldr r0, %1 \t\n\
     ldr r1, %2 \t\n\
     ldr r2, %3 \t\n\
     ldr p7, 0, r0, c0, c0, 0 \t\n\
     sdr r0, %0 \t\n\
     pop {r0-r4} \t\n\
    "
    : "=g"(ret) /* output operand */
    : "g" (r0), "g" (action), "g" (s) /* input operands */
    : "r0", "r1", "r2", "r3" /* clobbered registers */
    );

    return ret;
}
#else
#error Unsupported platform.
#endif
