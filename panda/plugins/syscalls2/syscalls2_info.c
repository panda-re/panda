#include <stdio.h>
#include <stdint.h>
#include <dlfcn.h>
#include <glib.h>
#include "syscalls2_info.h"
#include "syscalls2_int_fns.h"
#define PLUGIN_DEBUG PLUGIN_NAME ": "

syscall_info_t *syscall_info;


int load_syscall_info(void) {
    // XXX: we need to construct this string from information passed through -os
    char *syscall_info_dlname = g_strdup_printf("dso_%s_gen_syscall_info_%s_%s.so", PLUGIN_NAME, "linux", "x86");

    dlerror();  // clear errors
    void *syscall_info_dl = dlopen(syscall_info_dlname, RTLD_NOW|RTLD_NODELETE);
    if (syscall_info_dl == NULL) {
        fprintf(stderr, PLUGIN_DEBUG "%s\n", dlerror());
        g_free(syscall_info_dlname);
        return -1;
    }

    dlerror();  // clear errors
    syscall_info = (syscall_info_t *)dlsym(syscall_info_dl, "__syscall_info_a");
    if (syscall_info == NULL) {
        fprintf(stderr, PLUGIN_DEBUG "%s\n", dlerror());
        dlclose(syscall_info_dl);
        g_free(syscall_info_dlname);
        return -1;
    }

    fprintf(stderr, "loaded sytem call info from %s\n", syscall_info_dlname);
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

