#ifndef __LIBFI_INT_FNS_H__
#define __LIBFI_INT_FNS_H__

// add a callback for enter (issenter = 1) or exit (isenter = 0) of function named fnname
// libname really is name of source file with that fn in it.
// numargs is how many args we should grab from stack when we enter that fn.
// cb is the callback itself
void libfi_add_callback(char *libname, char *fnname, int isenter, uint32_t numargs, libfi_cb_t cb);

#endif
