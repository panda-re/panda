string read_str(CPUState* cpu, target_ulong ptr);
int get_numelements_hash(CPUState* cpu, target_ulong dt_hash);
int get_numelements_gnu_hash(CPUState* cpu, target_ulong gnu_hash);
int get_numelements_symtab(CPUState* cpu, target_ulong base, target_ulong dt_hash, target_ulong gnu_hash, target_ulong dynamic_section, target_ulong symtab, int numelements_dyn);