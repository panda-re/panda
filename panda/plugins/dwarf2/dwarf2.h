#ifndef __DWARF2_H_
#define __DWARF2_H_

typedef void (* on_dwarf2_line_change_t)(CPUState *env, target_ulong pc, const char *file_name, const char *funct_name, unsigned long long lno);

#endif
