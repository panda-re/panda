#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <dlfcn.h>
#include <glib.h>
#include "panda/plugin.h"
#include "syscalls2_info.h"
#include "syscalls2_int_fns.h"

const syscall_info_t *syscall_info;
const syscall_meta_t *syscall_meta;

int load_syscall_info(void) {
    gchar *syscall_info_dlname = NULL;
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    const gchar *arch = "x86";
#elif defined(TARGET_ARM) &&!defined(TARGET_AARCH64)
    const gchar *arch = "arm";
#elif defined(TARGET_ARM) &&defined(TARGET_AARCH64)
    const gchar *arch = "arm64";
#elif defined(TARGET_MIPS)
    const gchar *arch = "mips";
#elif defined(TARGET_X86_64)
    const gchar *arch = "x64";
#else
    // will fail on dlopen because dso file won't exist
    const gchar *arch = "unknown";
#endif

    if (panda_os_familyno == OS_WINDOWS) {
    	// don't support 64-bit Windows (yet)
    	assert(panda_os_bits == 32);

        // for windows, take into account the panda_os_variant
        syscall_info_dlname = g_strdup_printf("%s_dso_info_%s_%s_%s" HOST_DSOSUF, PLUGIN_NAME, panda_os_family, panda_os_variant, arch);
    }
    else {
    	assert((panda_os_bits == 32) || (panda_os_bits == 64));

        // for everything else (i.e. linux), only use panda_os_family
        syscall_info_dlname = g_strdup_printf("%s_dso_info_%s_%s" HOST_DSOSUF, PLUGIN_NAME, panda_os_family, arch);
    }

    dlerror();  // clear errors
    void *syscall_info_dl = dlopen(syscall_info_dlname, RTLD_NOW|RTLD_NODELETE);
    if (syscall_info_dl == NULL) {
        LOG_ERROR("%s", dlerror());
        g_free(syscall_info_dlname);
        return -1;
    }

    dlerror();  // clear errors
    syscall_info = (syscall_info_t *)dlsym(syscall_info_dl, "__syscall_info_a");
    if (syscall_info == NULL) {
        LOG_ERROR("%s", dlerror());
        dlclose(syscall_info_dl);
        g_free(syscall_info_dlname);
        return -1;
    }

    dlerror();  // clear errors
    syscall_meta = (syscall_meta_t *)dlsym(syscall_info_dl, "__syscall_meta");
    if (syscall_meta == NULL) {
        LOG_ERROR("%s", dlerror());
        dlclose(syscall_info_dl);
        g_free(syscall_info_dlname);
        return -1;
    }

    LOG_INFO("loaded syscalls info from %s", syscall_info_dlname);
    dlclose(syscall_info_dl);
    g_free(syscall_info_dlname);
    return 0;
}

/* vim:set tabstop=4 softtabstop=4 expandtab: */
