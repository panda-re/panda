/*!
 * @file recctrlu.c
 * @brief Recording controller utility for PANDA.
 *
 * @author Manolis Stamatogiannakis manolis.stamatogiannakis@vu.nl
 *
 * @copyright This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 */
#include <stdio.h>
#include <string.h>
#include "recctrl.h"

/*
 * Reference for arch macros:
 *      https://sourceforge.net/p/predef/wiki/Architectures/
 * Reference for inline asm syntax:
 *      https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html
 * Default asm dialect is att.
 */

#if defined(__x86_64__) || defined(__i386__)
static inline int hc(recctrl_action_t action, char *s) {
    int eax = RECCTRL_MAGIC;
    int ret = RECCTRL_RET_ERROR;

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
static inline int hc(recctrl_action_t action, char *s) {
    unsigned long r0 = RECCTRL_MAGIC;
    int ret = RECCTRL_RET_ERROR;

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

int main(int argc, char *argv[]) {
    recctrl_action_t action;

    if (argc != 3) {
        goto help;
    } else if (!strcmp("toggle", argv[1])) {
        action = RECCTRL_ACT_TOGGLE;
    } else if (!strcmp("open_session", argv[1])) {
        action = RECCTRL_ACT_SESSION_OPEN;
    } else if (!strcmp("close_session", argv[1])) {
        action = RECCTRL_ACT_SESSION_CLOSE;
    } else {
        goto help;
    }

    int hcret = hc(action, argv[2]);
    int ret = 1;

    switch(hcret) {
    case RECCTRL_RET_ERROR:
        fprintf(stderr, "Error. Hypercall failed.\n");
        break;
    case RECCTRL_RET_NOOP:
        fprintf(stderr, "Success.\n");
        ret = 0;
        break;
    case RECCTRL_RET_START:
        fprintf(stderr, "Success. Started recording.\n");
        ret = 0;
        break;
    case RECCTRL_RET_STOP:
        fprintf(stderr, "Success. Stopped recording.\n");
        ret = 0;
        break;
    default:
        fprintf(stderr, "Error. Unknown hypercall return code: %d\n", ret);
        break;
    }

    return ret;

help:
    fprintf(stderr, "Syntax: %s <toggle|open_session|close_session> <replay_name>\n", argv[0]);
    return 1;
}

/* vim:set tabstop=4 softtabstop=4 expandtab: */
