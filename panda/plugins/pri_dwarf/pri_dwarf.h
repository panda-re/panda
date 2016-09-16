#ifndef __PRI_DWARF_H_
#define __PRI_DWARF_H_

typedef void (* on_pri_dwarf_line_change_t)(CPUState *env, target_ulong pc, const char *file_name, const char *funct_name, unsigned long long lno);

#endif
