#ifndef __LOADED_H_
#define __LOADED_H_

typedef void (* on_library_load_t)(CPUState *env, target_ulong pc, char *filename, target_ulong base_addr, target_ulong size);

#endif
