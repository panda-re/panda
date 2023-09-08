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
#elif defined(TARGET_MIPS) && defined(TARGET_MIPS64)
    const gchar *arch = "mips64";
#elif defined(TARGET_MIPS)
    const gchar *arch = "mips";
#elif defined(TARGET_X86_64)
    const gchar *arch = "x64";
#else
    // will fail on dlopen because dso file won't exist
    const gchar *arch = "unknown";
#endif

    if (panda_os_familyno == OS_WINDOWS) {
    	// don't support 64-bit Windows (yet) except for Windows 7 SP 0 and 1
    	assert((panda_os_bits == 32) ||
    	        (0 == strcmp(panda_os_variant, "7sp0")) ||
    	        (0 == strcmp(panda_os_variant, "7sp1")));

    	// Windows 7 is special - SP 0 and 1 are in same file
    	if (0 == strncmp(panda_os_variant, "7", 1)) {
    	    syscall_info_dlname = g_strdup_printf("%s_dso_info_%s_7_%s" HOST_DSOSUF, PLUGIN_NAME, panda_os_family, arch);
    	} else {
            // for windows, take into account the panda_os_variant
            syscall_info_dlname = g_strdup_printf("%s_dso_info_%s_%s_%s" HOST_DSOSUF, PLUGIN_NAME, panda_os_family, panda_os_variant, arch);
    	}
    }
    else {
    	assert((panda_os_bits == 32) || (panda_os_bits == 64));

        // for everything else (i.e. linux), only use panda_os_family
        syscall_info_dlname = g_strdup_printf("%s_dso_info_%s_%s" HOST_DSOSUF, PLUGIN_NAME, panda_os_family, arch);
    }

    dlerror();  // clear errors

    char* sys_info_dlname_path = panda_shared_library_path(syscall_info_dlname);
    if (sys_info_dlname_path == NULL) {
        fprintf(stderr, "Could not find %s\n", syscall_info_dlname);
        return -1;
    }

    void *syscall_info_dl = dlopen(sys_info_dlname_path, RTLD_NOW|RTLD_NODELETE);
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
