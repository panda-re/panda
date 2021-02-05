#define MAKE_HOOK_FN_START(upper_cb_name, temp_name_hooks, name_hooks, name, callback, value) \
    if (unlikely(! temp_name_hooks .empty())){ \
        for (auto &h: temp_name_hooks) { \
            name_hooks[h.asid].insert(h); \
        } \
        temp_name_hooks .clear(); \
    } \
    if (unlikely(name_hooks .empty())){ \
        panda_disable_callback(self, PANDA_CB_ ## upper_cb_name, callback); \
        return value; \
    } \
    target_ulong asid = panda_current_asid(cpu); \
    bool in_kernel = panda_in_kernel(cpu); \
    struct hook hook_container; \
    hook_container.addr = panda_current_pc(cpu); \
    set<struct hook>::iterator it;

#define HOOK_ASID_START(name_hooks)\
    it = name_hooks[asid].lower_bound(hook_container); \
    while(it != name_hooks[asid].end() && it->addr == hook_container.addr){ \
        auto h = *it; \
        if (likely(h.enabled)){ \
            if (h.asid == 0 || h.asid == asid){ \
                if (h.km == MODE_ANY || (in_kernel && h.km == MODE_KERNEL_ONLY) || (!in_kernel && h.km == MODE_USER_ONLY)){

#define MAKE_HOOK_FN_END(name_hooks) \
                    if (!h.enabled){ \
                        it = name_hooks[asid].erase(it); \
                        continue; \
                    } \
                    memcpy((void*)&(*it), (void*)&h, sizeof(struct hook)); \
                } \
            } \
        } \
        ++it; \
    } 

#define MAKE_HOOK_VOID(upper_cb_name, temp_name_hooks, name_hooks, name, callback, ...) \
    MAKE_HOOK_FN_START(upper_cb_name, temp_name_hooks, name_hooks, name, callback, )\
    HOOK_ASID_START(name_hooks) \
    (*(h.cb.name))(__VA_ARGS__); \
    MAKE_HOOK_FN_END(name_hooks) \
    asid = 0; \
    HOOK_ASID_START(name_hooks) \
    (*(h.cb.name))(__VA_ARGS__); \
    MAKE_HOOK_FN_END(name_hooks)

#define MAKE_HOOK_BOOL(upper_cb_name, temp_name_hooks, name_hooks, name, callback, ...) \
    MAKE_HOOK_FN_START(upper_cb_name, temp_name_hooks, name_hooks, name, callback, false) \
    HOOK_ASID_START(name_hooks) \
    MAKE_HOOK_FN_END(name_hooks) \
    asid = 0; \
    HOOK_ASID_START(name_hooks) \
    ret |= (*(h.cb.name))(__VA_ARGS__); \
    MAKE_HOOK_FN_END(name_hooks)
