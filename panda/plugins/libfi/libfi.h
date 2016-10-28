#ifndef __LIBFI_H__
#define __LIBFI_H__


//typedef void (* libfi_cb_t)(CPUState *env, target_ulong pc, const char *file_name, const char *funct_name);
typedef void (* libfi_cb_t)(CPUState *env, target_ulong pc, uint8_t *arg);

#endif
