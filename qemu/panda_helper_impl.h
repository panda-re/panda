/* PANDABEGINCOMMENT PANDAENDCOMMENT */
void helper_panda_insn_exec(target_ulong pc) {
    // PANDA instrumentation: before basic block 
    panda_cb_list *plist;
    for(plist = panda_cbs[PANDA_CB_INSN_EXEC]; plist != NULL; plist = plist->next) {
        plist->entry.insn_exec(env, pc);
    }
}


