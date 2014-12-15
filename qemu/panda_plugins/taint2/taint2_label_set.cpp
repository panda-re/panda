#include <map>

#include "label_set.h"

std::map<std::pair<LabelSetP, LabelSetP>, LabelSetP> *memoized_unions = NULL;

void label_set_iter(LabelSetP ls, void (*leaf)(uint32_t, void *), void *user) {
    if (!ls) return;
    
    if (ls->child1) { // union
        label_set_iter(ls->child1, leaf, user);
        label_set_iter(ls->child2, leaf, user);
    } else {
        leaf(ls->label, user);
    }
}

LabelSetP label_set_union(LabelSetP ls1, LabelSetP ls2) {
    if (ls1 == ls2) {
        return ls1;
    } else if (ls1 && ls2) {
        LabelSetP min = std::min(ls1, ls2);
        LabelSetP max = std::max(ls1, ls2);
        std::pair<LabelSetP, LabelSetP> minmax(min, max);

        if (!memoized_unions)
            memoized_unions = new std::map<std::pair<LabelSetP, LabelSetP>, LabelSetP>();
        qemu_log_mask(CPU_LOG_TAINT_OPS, "  MEMO: %lu, %lu\n", (uint64_t)min, (uint64_t)max);

        auto it = memoized_unions->find(minmax);
        if (it != memoized_unions->end()) {
            return it->second;
        }
        qemu_log_mask(CPU_LOG_TAINT_OPS, "  NOT FOUND\n");

        LabelSetP result = new struct LabelSet;
        //labelset_count++;

        result->child1 = min;
        result->child2 = max;

        memoized_unions->insert(std::make_pair(minmax, result));
        qemu_log_mask(CPU_LOG_TAINT_OPS, "  INSERTED\n");
        return result;
    } else if (ls1) {
        return ls1;
    } else if (ls2) {
        return ls2;
    } else return nullptr;
}

LabelSetP label_set_singleton(uint32_t label) {
    LabelSetP result = new struct LabelSet;
    //labelset_count++;

    result->child1 = nullptr;
    result->label = label;
    return result;
}
