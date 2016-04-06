#ifndef __DWARFP_H_
#define __DWARFP_H_

typedef void (* on_dwarfp_line_change_t)(CPUState *env, target_ulong pc, const char *file_name, const char *funct_name, unsigned long long lno);

#endif
