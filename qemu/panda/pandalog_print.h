void pprint_ple(Panda__LogEntry *ple);
void pprint_process(const char *label, Panda__Process *p);
void pprint_process_file(Panda__ProcessFile *pf);
void pprint_process_key(Panda__ProcessKey *pk);
void pprint_process_key_value(Panda__ProcessKeyValue *pkv);
void pprint_process_key_index(Panda__ProcessKeyIndex *pki);
void pprint_section(Panda__Section *section);
void pprint_local_port(Panda__LocalPort *port);
void pprint_panda_vm(Panda__VirtualMemory *pvm);

void pprint_call_stack(Panda__CallStack *cs);

#ifdef LAVA
void pprint_attack_point(Panda__AttackPoint *ap);
#endif

void pprint_src_info(Panda__SrcInfo *si);
void pprint_taint_query_unique_label_set(Panda__TaintQueryUniqueLabelSet *tquls);
void pprint_taint_query(Panda__TaintQuery *tq);
void pprint_taint_query_hypercall(Panda__TaintQueryHypercall *tqh);
void pprint_tainted_branch(Panda__TaintedBranch *tb);
void pprint_tainted_instr(Panda__TaintedInstr *tb);
void pprint_tainted_instr_summary(Panda__TaintedInstrSummary *tb);
