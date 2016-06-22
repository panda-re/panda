#include <assert.h>
#include <stdint.h>
#include <glib.h>

extern "C" {
#include "disas.h"
#include "panda_plugin.h"
}
#include "panda_common.h"

target_ulong panda_current_pc(CPUState *env) {
    target_ulong pc, cs_base;
    int flags;
    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
    return pc;
}

#ifdef TARGET_ARM
// ARM: stolen from target-arm/helper.c
static uint32_t arm_get_vaddr_table(CPUState *env, uint32_t address)
{
  uint32_t table;

  if (address & env->cp15.c2_mask)
    table = env->cp15.c2_base1 & 0xffffc000;
  else
    table = env->cp15.c2_base0 & env->cp15.c2_base_mask;

  return table;
}
#endif

/*
  returns current asid or address-space id.
  architecture-independent
*/
target_ulong panda_current_asid(CPUState *env) {
#if (defined TARGET_I386 || defined TARGET_X86_64)
  return env->cr[3];
#elif defined(TARGET_ARM)
  return arm_get_vaddr_table(env, panda_current_pc(env));
#else
#error "panda_current_asid() not implemented for target architecture."
  return 0;
#endif
}

/*
  returns true if we are currently executing in kernel-mode
*/

bool panda_in_kernel(CPUState *env) {
#if defined(TARGET_I386)
    return ((env->hflags & HF_CPL_MASK) == 0);
#elif defined(TARGET_ARM)
    return ((env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_SVC);
#else
#error "panda_in_kernel() not implemented for target architecture."
    return false;
#endif
}


void panda_disas(FILE *out, void *code, unsigned long size) {
    disas(out,code,size);
}

const char * valid_os[] = {
    "windows-32-xpsp2", 
    "windows-32-xpsp3", 
    "windows-32-7", 
    "linux-32-*",
    "linux-64-*",
    NULL
};



PandaOsType panda_os_type = OST_UNKNOWN;
gchar *panda_os_name = NULL;
uint32_t panda_os_bits = 0;  // 32 or 64
gchar *panda_os_details = NULL;

void panda_set_os_name(char *os_name) {
    // set os name and split it
    panda_os_name = g_strdup(os_name);
    gchar **osparts = g_strsplit(panda_os_name, "-", 3);

    // set os type
    if (0 == g_ascii_strncasecmp("windows", osparts[0], strlen("windows"))) { panda_os_type = OST_WINDOWS; }
    else if (0 == g_ascii_strncasecmp("linux", osparts[0], strlen("linux"))) { panda_os_type = OST_LINUX; }
    else { panda_os_type = OST_UNKNOWN; }

    // set os bits
    if (0 == g_ascii_strncasecmp("32", osparts[1], strlen("32"))) { panda_os_bits = 32; }
    else if (0 == g_ascii_strncasecmp("64", osparts[1], strlen("64"))) { panda_os_bits = 64; }
    else { panda_os_bits = 0; }

    // set os details
    panda_os_details = g_strdup(osparts[2]);

    // abort for invalid os type/bits
    assert (!(panda_os_type == OST_UNKNOWN));
    assert (panda_os_bits != 0);
    g_strfreev(osparts);

    gboolean os_details_ok = FALSE;
    if (panda_os_type == OST_WINDOWS) {
        for (const char **os=valid_os; *os != NULL; os++) {
            if (0 == strcmp(panda_os_name, *os)) {
                os_details_ok = TRUE;
                break;
            }
        }

        if (!os_details_ok) {
            fprintf(stderr, "os_name=[%s] is not on the list :\n", panda_os_name);
            for (const char **os=valid_os; *os != NULL; os++) {
                fprintf(stderr, "\t[%s]\n", *os);
            }
        }
    }
    else if (panda_os_type == OST_LINUX) {
        // Don't do any further checking on panda_os_details for linux.
        //
        // Currently panda_os_details is only used by the osi plugin to determine
        // what arguments to pass to the osi_linux plugin.
        // However, the list of acceptable arguments is not known at compile time,
        // because osi_linux reads it from kernelinfo.conf.
        os_details_ok = TRUE;
    }
    assert (os_details_ok);

    printf ("os_type=%d bits=%d os_details=[%s]\n", panda_os_type, panda_os_bits, panda_os_details); 
}
