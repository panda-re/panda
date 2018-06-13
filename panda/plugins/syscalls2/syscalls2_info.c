#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <dlfcn.h>
#include <glib.h>
#include "panda/plugin.h"
#include "syscalls2_info.h"
#include "syscalls2_int_fns.h"

syscall_info_t *syscall_info;

int load_syscall_info(void) {
    gchar *syscall_info_dlname = NULL;
#if defined(TARGET_I386)
    const gchar *arch = "x86";
#elif defined(TARGET_ARM)
    const gchar *arch = "arm";
#else
    // will fail on dlopen because dso file won't exist
    const gchar *arch = "unknown";
#endif

    if (panda_os_familyno == OS_WINDOWS) {
        // for windows, take into account the panda_os_variant
        syscall_info_dlname = g_strdup_printf("dso_%s_gen_syscall_info_%s_%s_%s" HOST_DSOSUF, PLUGIN_NAME, panda_os_family, panda_os_variant, arch);
    }
    else {
        // for everything else (i.e. linux), only use panda_os_family
        syscall_info_dlname = g_strdup_printf("dso_%s_gen_syscall_info_%s_%s" HOST_DSOSUF, PLUGIN_NAME, panda_os_family, arch);
    }

    // panda_os_bits will be useful when support for 64bit operating systems is added
    // for now, just use it in this assertion to make the compiler happy
    assert(panda_os_bits == 32);

    dlerror();  // clear errors
    void *syscall_info_dl = dlopen(syscall_info_dlname, RTLD_NOW|RTLD_NODELETE);
    if (syscall_info_dl == NULL) {
        fprintf(stderr, PANDA_MSG "%s\n", dlerror());
        g_free(syscall_info_dlname);
        return -1;
    }

    dlerror();  // clear errors
    syscall_info = (syscall_info_t *)dlsym(syscall_info_dl, "__syscall_info_a");
    if (syscall_info == NULL) {
        fprintf(stderr, PANDA_MSG "%s\n", dlerror());
        dlclose(syscall_info_dl);
        g_free(syscall_info_dlname);
        return -1;
    }

    fprintf(stderr, PANDA_MSG "loaded syscalls info from %s\n", syscall_info_dlname);
    dlclose(syscall_info_dl);
    g_free(syscall_info_dlname);
    return 0;
}


syscall_info_t *get_syscall_info(uint32_t callno) {
    if (syscall_info != NULL) {
        return &syscall_info[callno];
    }
    else {
        return NULL;
    }
}

