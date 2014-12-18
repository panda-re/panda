#include <map>

#include "label_set.h"

std::map<std::pair<LabelSetP, LabelSetP>, LabelSetP> *memoized_unions = NULL;

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

std::set<uint32_t> label_set_render_set(LabelSetP ls) {
    return label_set_iter<std::set<uint32_t>, set_insert>(ls);
}

uint64_t label_set_render_uint(LabelSetP ls) {
    constexpr uint64_t zero = 0UL;
    return label_set_iter<uint64_t, bitset_insert, zero>(ls);
}
